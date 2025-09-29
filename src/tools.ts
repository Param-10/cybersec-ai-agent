/**
 * Security Analysis Tools for SecBot Cybersecurity Agent
 * Provides comprehensive cybersecurity analysis, threat detection, and incident response capabilities
 */
import { tool, type ToolSet } from "ai";
import { z } from "zod/v3";

import type { Chat } from "./server";
import { getCurrentAgent } from "agents";
import { scheduleSchema } from "agents/schedule";
import { SecurityAnalysisTools } from "./security-tools";

/**
 * Network log analysis tool for threat detection
 * Analyzes network logs for security threats and anomalies
 */
const analyzeNetworkLogs = tool({
  description: "Analyze network logs for security threats and anomalies",
  inputSchema: z.object({
    logData: z.string().describe("Network log entries to analyze"),
    analysisType: z.enum(["intrusion", "malware", "ddos", "reconnaissance", "general"]).describe("Type of security analysis to perform"),
    timeRange: z.string().optional().describe("Time range for log analysis (e.g., '1h', '24h')")
  }),
  execute: async ({ logData, analysisType, timeRange }) => {
    const securityTools = new SecurityAnalysisTools();
    return await securityTools.analyzeNetworkLogs({ logData, analysisType, timeRange });
  }
});

/**
 * Vulnerability assessment tool
 * Assess software, systems, or configurations for security vulnerabilities
 */
const vulnerabilityAssessment = tool({
  description: "Assess software, systems, or configurations for security vulnerabilities",
  inputSchema: z.object({
    target: z.string().describe("System, software, or configuration to assess"),
    scanType: z.enum(["quick", "comprehensive", "compliance"]).describe("Type of vulnerability scan to perform"),
    compliance: z.string().optional().describe("Compliance framework to check against (NIST, PCI-DSS, etc.)")
  }),
  execute: async ({ target, scanType, compliance }) => {
    const securityTools = new SecurityAnalysisTools();
    return await securityTools.performVulnerabilityAssessment({ target, scanType, compliance });
  }
});

/**
 * Security concept explanation tool
 * Provide detailed explanations of cybersecurity concepts, attacks, and defenses
 */
const explainSecurityConcept = tool({
  description: "Provide detailed explanations of cybersecurity concepts, attacks, and defenses",
  inputSchema: z.object({
    concept: z.string().describe("Security concept to explain"),
    skillLevel: z.enum(["beginner", "intermediate", "advanced"]).optional().describe("User's technical skill level for appropriate explanation depth"),
    includeExamples: z.boolean().optional().describe("Whether to include practical examples")
  }),
  execute: async ({ concept, skillLevel, includeExamples }) => {
    const securityTools = new SecurityAnalysisTools();
    return await securityTools.explainSecurityConcept({ concept, skillLevel, includeExamples });
  }
});

/**
 * Incident response guidance tool
 * Provide step-by-step incident response procedures and best practices
 */
const incidentResponseGuidance = tool({
  description: "Provide step-by-step incident response procedures and best practices",
  inputSchema: z.object({
    incidentType: z.enum(["malware", "data-breach", "ddos", "insider-threat", "phishing", "ransomware"]).describe("Type of security incident"),
    severity: z.enum(["low", "medium", "high", "critical"]).describe("Assessed severity of the incident"),
    affectedSystems: z.string().optional().describe("Description of affected systems or data")
  }),
  execute: async ({ incidentType, severity, affectedSystems }) => {
    const securityTools = new SecurityAnalysisTools();
    return await securityTools.provideIncidentResponseGuidance({ incidentType, severity, affectedSystems });
  }
});

const scheduleTask = tool({
  description: "A tool to schedule a task to be executed at a later time",
  inputSchema: scheduleSchema,
  execute: async ({ when, description }) => {
    // we can now read the agent context from the ALS store
    const { agent } = getCurrentAgent<Chat>();

    function throwError(msg: string): string {
      throw new Error(msg);
    }
    if (when.type === "no-schedule") {
      return "Not a valid schedule input";
    }
    const input =
      when.type === "scheduled"
        ? when.date // scheduled
        : when.type === "delayed"
          ? when.delayInSeconds // delayed
          : when.type === "cron"
            ? when.cron // cron
            : throwError("not a valid schedule input");
    try {
      agent!.schedule(input!, "executeTask", description);
    } catch (error) {
      console.error("error scheduling task", error);
      return `Error scheduling task: ${error}`;
    }
    return `Task scheduled for type "${when.type}" : ${input}`;
  }
});

/**
 * Tool to list all scheduled tasks
 * This executes automatically without requiring human confirmation
 */
const getScheduledTasks = tool({
  description: "List all tasks that have been scheduled",
  inputSchema: z.object({}),
  execute: async () => {
    const { agent } = getCurrentAgent<Chat>();

    try {
      const tasks = agent!.getSchedules();
      if (!tasks || tasks.length === 0) {
        return "No scheduled tasks found.";
      }
      return tasks;
    } catch (error) {
      console.error("Error listing scheduled tasks", error);
      return `Error listing scheduled tasks: ${error}`;
    }
  }
});

/**
 * Tool to cancel a scheduled task by its ID
 * This executes automatically without requiring human confirmation
 */
const cancelScheduledTask = tool({
  description: "Cancel a scheduled task using its ID",
  inputSchema: z.object({
    taskId: z.string().describe("The ID of the task to cancel")
  }),
  execute: async ({ taskId }) => {
    const { agent } = getCurrentAgent<Chat>();
    try {
      await agent!.cancelSchedule(taskId);
      return `Task ${taskId} has been successfully canceled.`;
    } catch (error) {
      console.error("Error canceling scheduled task", error);
      return `Error canceling task ${taskId}: ${error}`;
    }
  }
});

/**
 * Export all available security tools
 * These will be provided to the AI model to describe SecBot's cybersecurity capabilities
 */
export const tools = {
  analyzeNetworkLogs,
  vulnerabilityAssessment,
  explainSecurityConcept,
  incidentResponseGuidance,
  scheduleTask,
  getScheduledTasks,
  cancelScheduledTask
} satisfies ToolSet;

/**
 * Implementation of confirmation-required tools
 * This object contains the actual logic for tools that need human approval
 * Currently all security tools execute automatically for immediate assistance
 */
export const executions = {
  // All security tools have execute functions for immediate response
  // Add any tools here that require human confirmation
};
