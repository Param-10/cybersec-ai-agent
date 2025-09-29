# 🛡️ SecBot - Cybersecurity AI Agent

![SecBot Banner](./npm-agents-banner.svg)

<a href="https://deploy.workers.cloudflare.com/?url=https://github.com/yourusername/cybersec-ai-agent"><img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare"/></a>

**SecBot** is an AI-powered cybersecurity assistant built on Cloudflare's Agent platform. It provides educational guidance, simulated security analysis, and expert knowledge on cybersecurity topics through an interactive chat interface with optional voice input.

🌐 **[Live Demo](https://cybersec-ai-agent.bheleparamveer.workers.dev)**

## ⚠️ Important Limitations & Disclaimers

**SecBot is designed for educational and guidance purposes only:**

- 📚 **Educational Purpose**: Provides security concepts, best practices, and simulated analysis - not actual security scanning
- 🚫 **No Real System Access**: Cannot connect to or scan actual networks, databases, or systems  
- 🎯 **Simulated Analysis**: Security assessments are template-based, not live threat intelligence
- 👨‍💼 **Professional Consultation**: For critical security issues, always consult qualified cybersecurity professionals
- 🧪 **Not for Production**: Do not rely on SecBot for production security decisions

## ✨ Features

- 🛡️ **Cybersecurity Expertise**: Comprehensive knowledge of security concepts, vulnerabilities, and best practices
- 🔍 **Security Analysis Tools**: Simulated network log analysis, vulnerability assessments, and threat detection
- 🚨 **Incident Response**: Step-by-step guidance for various security incidents
- 🎤 **Voice Interface**: Optional speech recognition for hands-free interaction
- 📊 **Educational Content**: Detailed explanations with examples, prevention methods, and case studies
- 🎓 **Skill-Level Adaptation**: Tailors responses to beginner, intermediate, or advanced levels
- 🌙 **Professional UI**: Dark cybersecurity-themed interface with organized sample questions
- ⚡️ **Real-time Streaming**: Powered by Cloudflare Workers AI (Llama 3.3-70B)
- 💾 **Persistent Memory**: Conversation history via Durable Objects

## 🎯 Security Capabilities

### 📚 Security Education
- Cross-Site Scripting (XSS)
- SQL Injection attacks
- CSRF (Cross-Site Request Forgery)
- DDoS attacks and mitigation
- Phishing and social engineering
- Malware analysis and prevention
- OWASP Top 10 vulnerabilities

### 🔍 Security Analysis (Simulated)
- Network log analysis
- Vulnerability assessments
- Traffic pattern analysis
- Security configuration reviews

### 🚨 Incident Response
- Ransomware response procedures
- Data breach protocols
- Malware infection handling
- Phishing incident management

### 🛡️ Best Practices
- Password security guidelines
- WordPress security hardening
- Zero-trust implementation
- Security framework compliance

## 🚀 Prerequisites

- **Cloudflare Account** with Workers AI enabled
- **Node.js** 20.19+ or 22.12+
- **Basic cybersecurity knowledge** (recommended for optimal use)

## ⚡ Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/cybersec-ai-agent.git
cd cybersec-ai-agent
npm install
```

### 2. Environment Setup

Create a `.dev.vars` file:

```env
OPENAI_API_KEY=sk-dummy-key-we-will-use-workers-ai-instead
ENVIRONMENT=development
DEBUG_MODE=true
```

### 3. Configure Wrangler

Update `wrangler.jsonc` with your settings:

```jsonc
{
  "name": "your-secbot-name",
  "main": "src/server.ts",
  "ai": {
    "binding": "AI",
    "remote": true
  },
  "durable_objects": {
    "bindings": [
      {
        "name": "Chat",
        "class_name": "Chat",
        "script_name": "your-secbot-name"
      }
    ]
  }
}
```

### 4. Development

```bash
npm start
# Visit http://localhost:5173/
```

### 5. Deploy

```bash
npm run deploy
# Your SecBot will be available at: https://your-secbot-name.your-subdomain.workers.dev
```

## 📁 Project Structure

```
├── src/
│   ├── app.tsx           # Voice-enabled chat interface
│   ├── server.ts         # SecBot agent logic with Workers AI
│   ├── security-tools.ts # Core cybersecurity analysis tools
│   ├── tools.ts          # AI tool definitions for security
│   ├── styles.css        # Cybersecurity-themed UI styling
│   ├── client.tsx        # Client-side entry point
│   └── shared.ts         # Shared types and utilities
├── wrangler.jsonc        # Cloudflare Workers configuration
├── .dev.vars.example     # Environment variables template
└── README.md            # This file
```

## 🔧 Customization Guide

### Adding New Security Tools

Extend SecBot's capabilities by adding tools in `security-tools.ts`:

```typescript
async explainSecurityConcept(params: {
  concept: string;
  skillLevel: 'beginner' | 'intermediate' | 'advanced';
  includeExamples: boolean;
}): Promise<SecurityConceptExplanation> {
  // Add your custom security concept explanations
  const explanations = {
    'your_new_concept': {
      description: 'Your concept description',
      technicalDetails: 'Technical explanation based on skill level',
      prevention: ['Prevention method 1', 'Prevention method 2'],
      // ... additional fields
    }
  };
  // Implementation logic
}
```

Then register the tool in `tools.ts`:

```typescript
const explainYourConcept = tool({
  description: "Explain your custom security concept",
  parameters: z.object({
    concept: z.string(),
    skillLevel: z.enum(['beginner', 'intermediate', 'advanced']).default('intermediate')
  }),
  execute: async (params) => {
    const securityTools = new SecurityAnalysisTools();
    return await securityTools.explainSecurityConcept(params);
  }
});
```

### Customizing the UI

Modify the interface in `app.tsx`:

- **Sample Questions**: Update `quickActions` array with new categories and questions
- **Theme Colors**: Modify CSS variables in `styles.css` 
- **Voice Settings**: Configure speech recognition parameters
- **Analysis Modes**: Add new security analysis types to the dropdown

### Adding External Security APIs

Integrate real security services (with proper disclaimers):

```typescript
// Example: VirusTotal API integration
const checkFileHash = tool({
  description: "Check file hash against threat databases",
  parameters: z.object({
    hash: z.string(),
    hashType: z.enum(['md5', 'sha1', 'sha256'])
  }),
  execute: async ({ hash, hashType }) => {
    // Add proper API integration with error handling
    // Include disclaimers about data sharing
  }
});
```

## 🧪 Testing SecBot

Try these sample questions:

**Security Education:**
- "Explain Cross-Site Scripting (XSS) attacks"
- "What are the OWASP Top 10 vulnerabilities?"
- "How do SQL injection attacks work?"

**Incident Response:**
- "We detected ransomware. What should we do?"
- "Guide me through malware incident response"

**Best Practices:**
- "How do I secure my WordPress website?"
- "What's the best password security approach?"

## 🌐 Deployment Options

### Cloudflare Workers (Recommended)
```bash
npm run deploy
```

### Custom Domain
Update your `wrangler.jsonc`:
```jsonc
{
  "routes": [
    { "pattern": "secbot.yourdomain.com/*", "zone_name": "yourdomain.com" }
  ]
}
```

## 🔒 Security & Privacy

- **No Data Storage**: Conversations are stored temporarily in Durable Objects for session continuity only
- **No External APIs**: SecBot uses only Cloudflare Workers AI - no third-party API calls
- **No User Tracking**: No analytics or tracking beyond Cloudflare's standard metrics
- **Local Processing**: Voice input is processed in the browser, not sent to external services

## 📊 Usage Analytics

Monitor SecBot usage through Cloudflare Workers Analytics:
- Response times and performance
- Error rates and debugging
- Usage patterns (without personal data)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-security-tool`
3. Commit changes: `git commit -m "Add new security analysis tool"`
4. Push to branch: `git push origin feature/new-security-tool`
5. Create a Pull Request

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🆘 Support & Disclaimer

**This project is for educational purposes only.** For production security needs:

- Consult certified cybersecurity professionals
- Use enterprise-grade security tools
- Follow industry-standard security frameworks
- Implement proper security testing and validation

SecBot provides guidance and simulated analysis to help users learn cybersecurity concepts, but should never be relied upon for critical security decisions or actual threat detection.

## 📚 Learn More

- [Cloudflare Agents Documentation](https://developers.cloudflare.com/agents/)
- [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/)
- [OWASP Security Guidelines](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**⚠️ Remember: SecBot is an educational tool. Always consult cybersecurity professionals for critical security decisions.**