import type React from "react";
import { useState, useEffect, useRef, useCallback, useId } from "react";
import { useAgent } from "agents/react";
import { isToolUIPart } from "ai";
import { useAgentChat } from "agents/ai-react";
import type { UIMessage } from "@ai-sdk/react";
import type { tools } from "./tools";

// Component imports
import { Button } from "@/components/button/Button";
import { Card } from "@/components/card/Card";
import { Avatar } from "@/components/avatar/Avatar";
import { Textarea } from "@/components/textarea/Textarea";
import { MemoizedMarkdown } from "@/components/memoized-markdown";
import { ToolInvocationCard } from "@/components/tool-invocation-card/ToolInvocationCard";

// Icon imports
import {
  Trash,
  PaperPlaneTilt,
  Stop,
  Microphone,
  MicrophoneSlash
} from "@phosphor-icons/react";

interface SecurityContext {
  threatLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  analysisType: string;
  recommendedActions: string[];
}

// Extracted from inside component to satisfy noNestedComponentDefinitions
function SecurityAlert({ context }: { context: SecurityContext }) {
  const alertColors = {
    LOW: "bg-green-100 dark:bg-green-900/20 border-green-500 text-green-800 dark:text-green-400",
    MEDIUM:
      "bg-yellow-100 dark:bg-yellow-900/20 border-yellow-500 text-yellow-800 dark:text-yellow-400",
    HIGH: "bg-orange-100 dark:bg-orange-900/20 border-orange-500 text-orange-800 dark:text-orange-400",
    CRITICAL:
      "bg-red-100 dark:bg-red-900/20 border-red-500 text-red-800 dark:text-red-400"
  } as const;

  return (
    <div
      className={`border-l-4 p-4 mb-4 rounded-r-lg ${alertColors[context.threatLevel]}`}
    >
      <div className="flex items-center">
        <div className="flex-shrink-0">
          {context.threatLevel === "CRITICAL" && (
            <span className="text-2xl" role="img" aria-label="Critical alert">
              🚨
            </span>
          )}
          {context.threatLevel === "HIGH" && (
            <span className="text-2xl" role="img" aria-label="High alert">
              ⚠️
            </span>
          )}
          {context.threatLevel === "MEDIUM" && (
            <span className="text-2xl" role="img" aria-label="Medium alert">
              ⚡
            </span>
          )}
          {context.threatLevel === "LOW" && (
            <span className="text-2xl" role="img" aria-label="Information">
              ℹ️
            </span>
          )}
        </div>
        <div className="ml-3">
          <h3 className="text-lg font-medium">
            {context.threatLevel} Security Alert - {context.analysisType}
          </h3>
          {context.recommendedActions.length > 0 && (
            <div className="mt-2">
              <h4 className="font-medium">Recommended Actions:</h4>
              <ul className="list-disc list-inside mt-1">
                {context.recommendedActions.map((action) => (
                  <li
                    key={`${context.analysisType}-${context.threatLevel}-${action}`}
                    className="text-sm"
                  >
                    {action}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Tools that require human confirmation
const toolsRequiringConfirmation: (keyof typeof tools)[] = [];

// Browser speech recognition types
interface SpeechRecognitionEvent {
  results: SpeechRecognitionResultList;
}

interface SpeechRecognitionErrorEvent {
  error: string;
}

interface SpeechRecognitionConstructor {
  new (): SpeechRecognition;
}

interface SpeechRecognition {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  onresult: (event: SpeechRecognitionEvent) => void;
  onerror: (event: SpeechRecognitionErrorEvent) => void;
  onend: () => void;
  start(): void;
  stop(): void;
}

declare global {
  interface Window {
    SpeechRecognition: SpeechRecognitionConstructor;
    webkitSpeechRecognition: SpeechRecognitionConstructor;
  }
}

export default function SecBotInterface() {
  const [textareaHeight, setTextareaHeight] = useState("auto");
  const [isListening, setIsListening] = useState(false);
  const [voiceSupported, setVoiceSupported] = useState(false);
  const [securityContext] = useState<SecurityContext | null>(null);
  const [analysisMode, setAnalysisMode] = useState<string>("general");

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const recognitionRef = useRef<SpeechRecognition | null>(null);
  const synthesisRef = useRef<SpeechSynthesis | null>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  const agent = useAgent({
    agent: "chat"
  });

  const [agentInput, setAgentInput] = useState("");

  const {
    messages: agentMessages,
    addToolResult,
    clearHistory,
    status,
    sendMessage,
    stop
  } = useAgentChat<unknown, UIMessage<{ createdAt: string }>>({
    agent
  });

  const handleVoiceSubmit = useCallback(async () => {
    if (!agentInput.trim()) return;

    const message = agentInput;
    setAgentInput("");
    setTextareaHeight("auto");

    await sendMessage(
      {
        role: "user",
        parts: [{ type: "text", text: message }]
      },
      {
        body: {}
      }
    );
  }, [agentInput, sendMessage]);

  const handleVoiceInput = useCallback(
    (transcript: string) => {
      setAgentInput(transcript);
      setTimeout(() => {
        handleVoiceSubmit();
      }, 100);
    },
    [handleVoiceSubmit]
  );

  const initializeVoiceCapabilities = useCallback(() => {
    if ("webkitSpeechRecognition" in window || "SpeechRecognition" in window) {
      const SpeechRecognition =
        window.SpeechRecognition || window.webkitSpeechRecognition;
      recognitionRef.current = new SpeechRecognition();

      if (recognitionRef.current) {
        recognitionRef.current.continuous = false;
        recognitionRef.current.interimResults = false;
        recognitionRef.current.lang = "en-US";

        recognitionRef.current.onresult = (event: SpeechRecognitionEvent) => {
          const transcript = event.results[0][0].transcript;
          handleVoiceInput(transcript);
        };

        recognitionRef.current.onerror = (
          event: SpeechRecognitionErrorEvent
        ) => {
          console.error("Speech recognition error:", event.error);
          setIsListening(false);
        };

        recognitionRef.current.onend = () => {
          setIsListening(false);
        };
      }

      synthesisRef.current = window.speechSynthesis;
      setVoiceSupported(true);
    }
  }, [handleVoiceInput]);

  useEffect(() => {
    initializeVoiceCapabilities();
    // Always use dark mode for cybersecurity theme
    document.documentElement.classList.add("dark");
    document.documentElement.classList.remove("light");
  }, [initializeVoiceCapabilities]);

  useEffect(() => {
    scrollToBottom();
  }, [scrollToBottom]);

  useEffect(() => {
    agentMessages.length > 0 && scrollToBottom();
  }, [agentMessages, scrollToBottom]);

  // initializeVoiceCapabilities moved & memoized above

  const toggleVoiceInput = () => {
    if (!voiceSupported || !recognitionRef.current) return;

    if (isListening) {
      recognitionRef.current.stop();
      setIsListening(false);
    } else {
      recognitionRef.current.start();
      setIsListening(true);
    }
  };

  // handleVoiceInput memoized above

  // handleVoiceSubmit moved above & memoized

  const handleAgentInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setAgentInput(e.target.value);
  };

  const handleAgentSubmit = async (
    e: React.FormEvent,
    extraData: Record<string, unknown> = {}
  ) => {
    e.preventDefault();
    if (!agentInput.trim()) return;

    const message = agentInput;
    setAgentInput("");
    setTextareaHeight("auto");

    // Send message to agent
    await sendMessage(
      {
        role: "user",
        parts: [{ type: "text", text: message }]
      },
      {
        body: extraData
      }
    );
  };

  const pendingToolCallConfirmation = agentMessages.some((m: UIMessage) =>
    m.parts?.some(
      (part) =>
        isToolUIPart(part) &&
        part.state === "input-available" &&
        toolsRequiringConfirmation.includes(
          part.type.replace("tool-", "") as keyof typeof tools
        )
    )
  );

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  // (Removed nested SecurityAlert - external component is used)

  const quickActions = [
    {
      category: "🎓 Security Education",
      questions: [
        {
          label: "What is Cross-Site Scripting (XSS)?",
          command: "Explain Cross-Site Scripting (XSS) attacks"
        },
        {
          label: "How do SQL injection attacks work?",
          command: "Explain SQL injection attacks with examples"
        },
        {
          label: "What is a DDoS attack?",
          command: "Explain DDoS attacks and how to prevent them"
        },
        {
          label: "Tell me about phishing attacks",
          command: "Explain phishing attacks and prevention methods"
        }
      ]
    },
    {
      category: "🔍 Security Analysis",
      questions: [
        {
          label: "Analyze network logs",
          command:
            'Analyze these Apache logs for suspicious activity:\n192.168.1.100 - - [29/Sep/2025:10:15:32] "GET /admin/login.php" 200 1234\n192.168.1.100 - - [29/Sep/2025:10:15:33] "POST /admin/login.php" 401 567\n192.168.1.100 - - [29/Sep/2025:10:15:34] "POST /admin/login.php" 401 567'
        },
        {
          label: "Check for vulnerabilities",
          command:
            "Check Apache HTTP Server version 2.4.41 for security vulnerabilities"
        },
        {
          label: "Analyze suspicious traffic",
          command: "Analyze this network traffic for potential security threats"
        },
        {
          label: "Security assessment",
          command: "Perform a general security assessment of my web application"
        }
      ]
    },
    {
      category: "🚨 Incident Response",
      questions: [
        {
          label: "Ransomware detected",
          command:
            "We detected ransomware on our file server. Guide me through immediate response steps."
        },
        {
          label: "Data breach response",
          command: "What should I do if I suspect a data breach?"
        },
        {
          label: "Malware incident",
          command: "Help me respond to a malware infection on user workstation"
        },
        {
          label: "Phishing email received",
          command:
            "Users received suspicious phishing emails. What's the response procedure?"
        }
      ]
    },
    {
      category: "🛡️ Best Practices",
      questions: [
        {
          label: "Secure my WordPress site",
          command: "How do I secure my WordPress website?"
        },
        {
          label: "Password security guide",
          command: "What are the best practices for password security?"
        },
        {
          label: "OWASP Top 10",
          command: "What are the OWASP Top 10 vulnerabilities?"
        },
        {
          label: "Zero-trust security",
          command: "How do I implement a zero-trust security model?"
        }
      ]
    }
  ];

  return (
    <div className="cybersec-interface min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <HasWorkersAI />

      {/* Header */}
      <div className="border-b border-blue-800/30 bg-slate-800/50 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="text-3xl">🛡️</div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                SecBot
              </h1>
              <p className="text-xs text-slate-400">
                Cybersecurity AI Assistant
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={analysisMode}
              onChange={(e) => setAnalysisMode(e.target.value)}
              className="bg-slate-700 text-slate-200 border border-slate-600 rounded-lg px-3 py-1 text-sm"
            >
              <option value="general">General Security</option>
              <option value="threat-analysis">Threat Analysis</option>
              <option value="vulnerability">Vulnerability Assessment</option>
              <option value="incident-response">Incident Response</option>
              <option value="compliance">Compliance Check</option>
            </select>

            <Button
              variant="ghost"
              size="md"
              shape="square"
              className="rounded-full h-9 w-9 text-slate-400 hover:text-slate-200"
              onClick={clearHistory}
            >
              <Trash size={20} />
            </Button>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="max-w-6xl mx-auto p-4 flex flex-col min-h-[calc(100vh-5rem)]">
        {securityContext && <SecurityAlert context={securityContext} />}

        {/* Messages Container */}
        <div className="flex-1 overflow-y-auto space-y-4 mb-4">
          {agentMessages.length === 0 && (
            <div className="text-center py-12">
              <Card className="p-8 bg-slate-800/50 border-blue-800/30 max-w-2xl mx-auto">
                <div className="space-y-6">
                  <div className="flex justify-center">
                    <div className="bg-blue-500/10 text-blue-400 rounded-full p-4">
                      🛡️
                    </div>
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-slate-200 mb-2">
                      Welcome to SecBot! 🛡️
                    </h2>
                    <p className="text-slate-400 mb-6">
                      I'm your AI-powered cybersecurity assistant. I can help
                      you with:
                    </p>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-slate-300">
                        <span className="text-blue-400">🔍</span>
                        <span>Network log analysis and threat detection</span>
                      </div>
                      <div className="flex items-center gap-2 text-slate-300">
                        <span className="text-blue-400">🛡️</span>
                        <span>
                          Vulnerability assessment and security scanning
                        </span>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-slate-300">
                        <span className="text-blue-400">📚</span>
                        <span>Security concept explanation and education</span>
                      </div>
                      <div className="flex items-center gap-2 text-slate-300">
                        <span className="text-blue-400">🚨</span>
                        <span>Incident response guidance and procedures</span>
                      </div>
                    </div>
                  </div>

                  {/* Limitations and Disclaimers */}
                  <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                    <h3 className="text-amber-400 font-medium text-sm mb-2 flex items-center gap-2">
                      <span>⚠️</span> Important Limitations
                    </h3>
                    <div className="text-xs text-amber-200/80 space-y-1">
                      <p>
                        • <strong>Educational Purpose:</strong> SecBot provides
                        guidance and simulated analysis - not actual security
                        scanning
                      </p>
                      <p>
                        • <strong>No Real System Access:</strong> Cannot connect
                        to or scan actual networks, databases, or systems
                      </p>
                      <p>
                        • <strong>Simulated Analysis:</strong> Security
                        assessments are template-based, not live threat
                        intelligence
                      </p>
                      <p>
                        • <strong>Professional Consultation:</strong> For
                        critical security issues, consult qualified
                        cybersecurity professionals
                      </p>
                    </div>
                  </div>

                  <p className="text-slate-500 text-sm mt-4">
                    {voiceSupported
                      ? "Use the microphone for voice input, or type your security question below."
                      : "Type your security question below to get started."}
                  </p>
                </div>
              </Card>
            </div>
          )}

          {agentMessages.map((m, index) => {
            const isUser = m.role === "user";
            const showAvatar =
              index === 0 || agentMessages[index - 1]?.role !== m.role;

            return (
              <div key={m.id}>
                <div
                  className={`flex ${isUser ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`flex gap-3 max-w-[85%] ${isUser ? "flex-row-reverse" : "flex-row"}`}
                  >
                    {showAvatar && !isUser ? (
                      <Avatar username={"SecBot"} />
                    ) : (
                      !isUser && <div className="w-8" />
                    )}

                    <div className="space-y-2">
                      {m.parts?.map((part) => {
                        // Stable key derivation avoiding array index usage
                        if (part.type === "text") {
                          const textKey = `msg-${m.id}-text-${part.text.length}-${part.text.slice(0, 16)}`;
                          return (
                            <div key={textKey}>
                              <Card
                                className={`p-4 ${
                                  isUser
                                    ? "bg-blue-600/20 border-blue-500/30 rounded-br-none text-slate-200"
                                    : "bg-slate-800/50 border-slate-600/30 rounded-bl-none text-slate-200"
                                }`}
                              >
                                <MemoizedMarkdown
                                  id={textKey}
                                  content={part.text}
                                />
                              </Card>
                              <p
                                className={`text-xs text-slate-500 mt-1 ${
                                  isUser ? "text-right" : "text-left"
                                }`}
                              >
                                {formatTime(
                                  m.metadata?.createdAt
                                    ? new Date(m.metadata.createdAt)
                                    : new Date()
                                )}
                              </p>
                            </div>
                          );
                        }

                        if (isToolUIPart(part)) {
                          const toolCallId = part.toolCallId;
                          const toolName = part.type.replace("tool-", "");
                          const needsConfirmation =
                            toolsRequiringConfirmation.includes(
                              toolName as keyof typeof tools
                            );
                          const toolKey = `tool-${toolCallId}`;

                          return (
                            <ToolInvocationCard
                              key={toolKey}
                              toolUIPart={part}
                              toolCallId={toolCallId}
                              needsConfirmation={needsConfirmation}
                              onSubmit={({ toolCallId, result }) => {
                                addToolResult({
                                  tool: part.type.replace("tool-", ""),
                                  toolCallId,
                                  output: result
                                });
                              }}
                              addToolResult={(toolCallId, result) => {
                                addToolResult({
                                  tool: part.type.replace("tool-", ""),
                                  toolCallId,
                                  output: result
                                });
                              }}
                            />
                          );
                        }
                        return null;
                      })}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}

          {status === "streaming" && (
            <div className="flex justify-start">
              <div className="flex gap-3 max-w-[85%]">
                <Avatar username={"SecBot"} />
                <Card className="p-4 bg-slate-800/50 border-slate-600/30">
                  <div className="flex items-center gap-2 text-slate-400">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                      <div
                        className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"
                        style={{ animationDelay: "0.2s" }}
                      ></div>
                      <div
                        className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"
                        style={{ animationDelay: "0.4s" }}
                      ></div>
                    </div>
                    Analyzing security data...
                  </div>
                </Card>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Sample Questions */}
        {agentMessages.length === 0 && (
          <div className="mb-4">
            <h3 className="text-slate-400 font-medium mb-2 text-center">
              Try these sample questions:
            </h3>
            <p className="text-slate-500 text-xs text-center mb-4">
              <em>
                Note: These demonstrate SecBot's educational capabilities with
                simulated responses
              </em>
            </p>
            <div className="space-y-4">
              {quickActions.map((category, _categoryIndex) => (
                <div
                  key={category.category}
                  className="bg-slate-800/30 rounded-lg p-4 border border-slate-600/20"
                >
                  <h4 className="text-slate-200 font-medium mb-3 text-sm">
                    {category.category}
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {category.questions.map((question, _questionIndex) => (
                      <button
                        type="button"
                        key={`${category.category}-${question.label}`}
                        className="p-3 bg-slate-700/30 hover:bg-slate-600/50 border border-slate-600/20 hover:border-blue-500/40 rounded-lg text-sm text-slate-300 hover:text-slate-100 transition-all duration-200 text-left"
                        onClick={() => {
                          setAgentInput(question.command);
                        }}
                      >
                        <span className="block font-medium text-blue-300">
                          {question.label}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Input Area */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAgentSubmit(e);
          }}
          className="relative"
        >
          <div className="flex items-end gap-2">
            {voiceSupported && (
              <Button
                type="button"
                onClick={toggleVoiceInput}
                className={`rounded-full p-3 h-12 w-12 flex items-center justify-center transition-all duration-200 ${
                  isListening
                    ? "bg-red-500 hover:bg-red-600 text-white animate-pulse"
                    : "bg-blue-500 hover:bg-blue-600 text-white"
                }`}
                disabled={status === "streaming"}
              >
                {isListening ? (
                  <MicrophoneSlash size={20} />
                ) : (
                  <Microphone size={20} />
                )}
              </Button>
            )}

            <div className="flex-1 relative">
              <Textarea
                disabled={pendingToolCallConfirmation || status === "streaming"}
                placeholder={
                  pendingToolCallConfirmation
                    ? "Please respond to the tool confirmation above..."
                    : isListening
                      ? "Listening... Speak your security question"
                      : "Ask about security threats, vulnerabilities, or get incident response guidance..."
                }
                className="w-full bg-slate-800/50 border border-slate-600/30 focus:border-blue-500/50 text-slate-200 placeholder-slate-500 rounded-2xl px-4 py-3 pr-16 resize-none min-h-[48px] max-h-[200px]"
                value={agentInput}
                onChange={(e) => {
                  handleAgentInputChange(e);
                  e.target.style.height = "auto";
                  e.target.style.height = `${Math.min(e.target.scrollHeight, 200)}px`;
                  setTextareaHeight(
                    `${Math.min(e.target.scrollHeight, 200)}px`
                  );
                }}
                onKeyDown={(e) => {
                  if (
                    e.key === "Enter" &&
                    !e.shiftKey &&
                    !e.nativeEvent.isComposing
                  ) {
                    e.preventDefault();
                    handleAgentSubmit(e as unknown as React.FormEvent);
                  }
                }}
                rows={1}
                style={{ height: textareaHeight }}
              />

              <div className="absolute bottom-2 right-2">
                {status === "submitted" || status === "streaming" ? (
                  <button
                    type="button"
                    onClick={stop}
                    className="p-2 rounded-full bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-slate-200 transition-colors"
                  >
                    <Stop size={16} />
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={pendingToolCallConfirmation || !agentInput.trim()}
                    className="p-2 rounded-full bg-blue-500 hover:bg-blue-600 disabled:bg-slate-600 disabled:text-slate-500 text-white transition-colors"
                  >
                    <PaperPlaneTilt size={16} />
                  </button>
                )}
              </div>
            </div>
          </div>

          {isListening && (
            <div className="flex items-center justify-center gap-2 mt-2 text-red-400">
              <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></div>
              <span className="text-sm">
                Listening... Speak your security question
              </span>
            </div>
          )}
        </form>

        {/* Footer Disclaimer */}
        <div className="mt-4 text-center text-xs text-slate-500 border-t border-slate-700/30 pt-4">
          SecBot provides educational cybersecurity guidance. For production
          systems, consult professional security services.
        </div>
      </div>
    </div>
  );
}

// Component to check Workers AI availability (replaces OpenAI key check)
const hasWorkersAIPromise = fetch("/check-open-ai-key").then((res) =>
  res.json<{ success: boolean; provider?: string; model?: string }>()
);

function HasWorkersAI() {
  const [hasWorkersAI, setHasWorkersAI] = useState<{
    success: boolean;
    provider?: string;
    model?: string;
  } | null>(null);
  const workersAITitleId = useId();

  useEffect(() => {
    hasWorkersAIPromise.then(setHasWorkersAI).catch(() => {
      setHasWorkersAI({ success: false });
    });
  }, []);

  if (!hasWorkersAI) return null;

  if (!hasWorkersAI.success) {
    return (
      <div className="fixed top-0 left-0 right-0 z-50 bg-red-500/10 backdrop-blur-sm">
        <div className="max-w-3xl mx-auto p-4">
          <div className="bg-slate-800 rounded-lg shadow-lg border border-red-600/30 p-4">
            <div className="flex items-start gap-3">
              <div className="p-2 bg-red-900/30 rounded-full">
                <svg
                  role="img"
                  aria-labelledby={workersAITitleId}
                  className="w-5 h-5 text-red-400"
                  xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <title id={workersAITitleId}>Workers AI not available</title>
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-red-400 mb-2">
                  Workers AI Not Available
                </h3>
                <p className="text-slate-300 mb-1">
                  SecBot requires Cloudflare Workers AI to function. Please
                  ensure your Worker has AI binding configured.
                </p>
                <p className="text-slate-400 text-sm">
                  Check your wrangler.jsonc configuration and ensure AI binding
                  is properly set up.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return null;
}
