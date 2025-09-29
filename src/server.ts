import { routeAgentRequest, type Schedule } from "agents";

import { getSchedulePrompt } from "agents/schedule";

import { AIChatAgent } from "agents/ai-chat-agent";

// Type definitions
interface SecurityContext {
  domain?: string;
  urgency?: string;
  analysisType?: string;
  detectedThreat?: string;
}

interface MessagePart {
  type: string;
  text?: string;
}

interface Message {
  parts: MessagePart[];
}

interface SecurityInteraction {
  userQuery: string;
  agentResponse: string;
  securityContext: SecurityContext;
  usage: unknown;
  timestamp: string;
}

interface DurableObjectState {
  storage: {
    get(key: string): Promise<unknown>;
    put(key: string, value: unknown): Promise<void>;
  };
}
import {
  generateId,
  streamText,
  type StreamTextOnFinishCallback,
  stepCountIs,
  createUIMessageStream,
  convertToModelMessages,
  createUIMessageStreamResponse,
  type ToolSet
} from "ai";
import { createWorkersAI } from "workers-ai-provider";
import { cleanupMessages } from "./utils";
import { tools } from "./tools";

interface Env {
  AI: Ai;
  Chat: DurableObjectNamespace;
}

const model = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
// Cloudflare AI Gateway
// const openai = createOpenAI({
//   apiKey: env.OPENAI_API_KEY,
//   baseURL: env.GATEWAY_BASE_URL,
// });

/**
 * SecBot Chat Agent - AI-powered cybersecurity assistant
 * Provides expert cybersecurity analysis, threat detection, and incident response guidance
 */
export class Chat extends AIChatAgent<Env> {
  private userSkillLevel: "beginner" | "intermediate" | "advanced" =
    "intermediate";

  /**
   * Handles incoming chat messages and manages the response stream with cybersecurity focus
   */
  async onChatMessage(
    onFinish: StreamTextOnFinishCallback<ToolSet>,
    _options?: { abortSignal?: AbortSignal }
  ) {
    // Collect all tools, including MCP tools (auto-executed, no confirmation UI)
    const allTools = { ...tools, ...this.mcp.getAITools() };

    // Analyze user query for security context
    const lastMessage = this.messages[this.messages.length - 1];
    const securityContext = await this.analyzeSecurityContext(lastMessage);

    const stream = createUIMessageStream({
      execute: async ({ writer }) => {
        // Clean up incomplete tool calls (we now rely on ai SDK to auto-execute tools)
        const cleanedMessages = cleanupMessages(this.messages);

        // Create Workers AI provider
        const workersAI = createWorkersAI({
          binding: this.env.AI
        });

        const result = streamText({
          model: workersAI(model as Parameters<typeof workersAI>[0]),
          system: this.generateSecuritySystemPrompt(securityContext),
          messages: convertToModelMessages(cleanedMessages),
          tools: allTools,
          onFinish: async (finishResult) => {
            // Log security interaction
            await this.logSecurityInteraction({
              userQuery:
                typeof lastMessage.parts[0] === "object" &&
                lastMessage.parts[0].type === "text"
                  ? lastMessage.parts[0].text
                  : "Non-text message",
              agentResponse: finishResult.text,
              securityContext,
              usage: finishResult.usage,
              timestamp: new Date().toISOString()
            });

            // Call the original onFinish callback
            if (onFinish) {
              onFinish(finishResult as never);
            }
          },
          stopWhen: stepCountIs(10)
        });

        writer.merge(result.toUIMessageStream());
      }
    });

    return createUIMessageStreamResponse({ stream });
  }

  /**
   * Generate cybersecurity-focused system prompt based on context
   */
  private generateSecuritySystemPrompt(context: SecurityContext): string {
    return `You are SecBot, an expert cybersecurity AI assistant with the following capabilities:

🛡️ CORE EXPERTISE:
- Network security analysis and threat detection
- Vulnerability assessment and penetration testing guidance
- Incident response and forensic analysis
- Security best practices and compliance guidance
- Code security review and secure development practices

🎯 CURRENT CONTEXT:
- User skill level: ${this.userSkillLevel}
- Security domain: ${context.domain || "general"}
- Analysis type: ${context.analysisType || "consultative"}
- Urgency level: ${context.urgency || "normal"}

📋 RESPONSE GUIDELINES:
- Provide accurate, ethical security guidance only
- Explain concepts appropriate for ${this.userSkillLevel} level
- Include practical, actionable recommendations
- Cite security frameworks (NIST, OWASP, CIS) when relevant
- Never provide guidance for illegal or malicious activities
- Keep explanations clear and comprehensive
- Always prioritize defensive security measures
 - IMPORTANT: For general conceptual questions (e.g., that start with "What is", "Explain", "Describe", or "How does"), answer directly WITHOUT invoking tools.
 - ONLY invoke tools for: network log analysis, vulnerability assessments, incident/response guidance, scheduled tasks, or when the user explicitly asks to "analyze", "scan", "assess", "schedule", or provide an incident response.

🔧 AVAILABLE TOOLS:
- Network log analysis and threat detection
- Vulnerability scanning and assessment
- Security concept explanation and education
- Incident response procedure guidance
- Security policy and compliance checking

Remember: You are an educational and defensive security assistant. Always promote ethical hacking practices and legal compliance.

${getSchedulePrompt({ date: new Date() })}

If the user asks to schedule a security task, use the schedule tool to schedule the task.`;
  }

  /**
   * Analyze user message for security context and urgency
   */
  private async analyzeSecurityContext(
    message: Message
  ): Promise<SecurityContext> {
    const content =
      typeof message.parts[0] === "object" && message.parts[0].type === "text"
        ? message.parts[0].text || ""
        : "";

    const securityKeywords = {
      vulnerability: { domain: "vuln-assessment", urgency: "high" },
      malware: { domain: "threat-analysis", urgency: "high" },
      phishing: { domain: "threat-analysis", urgency: "medium" },
      incident: { domain: "incident-response", urgency: "high" },
      firewall: { domain: "network-security", urgency: "low" },
      penetration: { domain: "pentest", urgency: "medium" },
      "sql injection": { domain: "web-security", urgency: "high" },
      xss: { domain: "web-security", urgency: "high" },
      ddos: { domain: "network-security", urgency: "high" },
      ransomware: { domain: "malware-analysis", urgency: "critical" },
      breach: { domain: "incident-response", urgency: "critical" }
    };

    for (const [keyword, context] of Object.entries(securityKeywords)) {
      if (content.toLowerCase().includes(keyword)) {
        return {
          ...context,
          analysisType: "targeted",
          detectedThreat: keyword
        };
      }
    }

    return {
      domain: "general",
      urgency: "normal",
      analysisType: "consultative"
    };
  }

  /**
   * Log security interaction for analysis and improvement
   */
  private async logSecurityInteraction(
    interaction: SecurityInteraction
  ): Promise<void> {
    try {
      // Check if Durable Object state is available (might not be in local dev)
      if (!this.state || !(this.state as DurableObjectState)?.storage) {
        // Silently skip logging in local development
        return;
      }

      const stored = await (this.state as DurableObjectState).storage.get(
        "security_interactions"
      );
      const interactions: SecurityInteraction[] = Array.isArray(stored)
        ? (stored as SecurityInteraction[])
        : [];
      interactions.push(interaction);

      // Keep only last 100 interactions
      if (interactions.length > 100) {
        interactions.splice(0, interactions.length - 100);
      }

      await (this.state as DurableObjectState).storage.put(
        "security_interactions",
        interactions
      );
    } catch (error: unknown) {
      console.error("Error logging security interaction:", error);
    }
  }
  async executeTask(description: string, _task: Schedule<string>) {
    await this.saveMessages([
      ...this.messages,
      {
        id: generateId(),
        role: "user",
        parts: [
          {
            type: "text",
            text: `Running scheduled task: ${description}`
          }
        ],
        metadata: {
          createdAt: new Date()
        }
      }
    ]);
  }
}

/**
 * Worker entry point that routes incoming requests to the SecBot agent
 */
export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Check if Workers AI is available (replaces OpenAI key check)
    if (url.pathname === "/check-open-ai-key") {
      const hasWorkersAI = !!env.AI;
      return Response.json({
        success: hasWorkersAI,
        provider: "Workers AI",
        model: model
      });
    }

    // Health check endpoint
    if (url.pathname === "/health") {
      return Response.json({
        status: "healthy",
        agent: "SecBot",
        version: "1.0.0",
        timestamp: new Date().toISOString()
      });
    }

    // Route the request to our SecBot agent or return 404 if not found
    return (
      (await routeAgentRequest(request, env)) ||
      new Response("SecBot endpoint not found", {
        status: 404,
        headers: { "Content-Type": "application/json" }
      })
    );
  }
} satisfies ExportedHandler<Env>;
