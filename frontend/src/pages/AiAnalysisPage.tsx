import React, { useState, useEffect, useRef } from 'react';
import {
  BrainCircuit,
  Terminal,
  Send,
  Trash2,
  Download,
  Copy,
  Check,
  Code2,
  Sparkles,
  ShieldCheck,
  Cpu,
  RefreshCw,
  MessageSquare,
  Flame,
  ArrowRight,
  Shield,
  Layers,
  HelpCircle,
  FileCode,
  Activity,
  User,
  Zap
} from 'lucide-react';
import { api } from '../services/api';
import { downloadFile } from '../utils/download';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  provider?: string;
  model?: string;
  duration_ms?: number;
  is_fallback?: boolean;
}

export const AiAnalysisPage: React.FC = () => {
  // Chat State
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [questionInput, setQuestionInput] = useState<string>('');
  const [qaLoading, setQaLoading] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [llmStatus, setLlmStatus] = useState<any | null>(null);
  const [quickCategories, setQuickCategories] = useState<any[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  // Default Initial Message
  useEffect(() => {
    const init = async () => {
      try {
        const [statusRes, questionsRes] = await Promise.all([
          api.getLLMStatus().catch(() => null),
          api.getQuickQuestions().catch(() => ({ categories: [] }))
        ]);
        setLlmStatus(statusRes);
        setQuickCategories(questionsRes?.categories || []);

        // Initial welcome message
        setChatHistory([
          {
            id: 'welcome-msg',
            role: 'assistant',
            content: `### 👋 Welcome to SOC CHESS AI Copilot

I am your **Autonomous AI Assistant & Cybersecurity Specialist**. You can ask me **anything** — whether you need general assistance, programming help, theoretical explanations, or hands-on cyber threat operations:

- 🛡️ **Cybersecurity Deep-Dives**: Attack mechanics (SQLi, XSS, Ransomware, DDoS, C2 beacons), MITRE ATT&CK mappings, and adversary profiles.
- 💻 **Software & Automation**: Write Python port scanners, packet sniffers, Bash IP blockers, PowerShell event auditors, and SQL queries.
- 📊 **SIEM & Detection**: Generate real-time **Splunk SPL** queries, **YARA** byte patterns, **Sigma** rules, and **Wireshark** display filters.
- 💡 **General Knowledge & IT**: Explain Zero Trust, symmetric vs asymmetric encryption, TCP 3-way handshakes, DNS resolution, and the OSI model.

**Type any question below or choose a prompt to begin!**`,
            timestamp: new Date().toLocaleTimeString(),
            provider: 'SOC CHESS AI Gateway',
            model: 'NVIDIA NIM + Universal Expert Engine',
            is_fallback: false
          }
        ]);
      } catch (err) {
        console.error('Failed to initialize AI Copilot:', err);
      }
    };
    init();
  }, []);

  // Auto-scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistory, qaLoading]);

  // Copy code utility
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Submit Question to AI
  const handleAsk = async (customText?: string) => {
    const q = (customText || questionInput).trim();
    if (!q || qaLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: q,
      timestamp: new Date().toLocaleTimeString()
    };

    setChatHistory((prev) => [...prev, userMsg]);
    setQuestionInput('');
    setQaLoading(true);

    try {
      // Recent turns for contextual memory
      const turns = chatHistory.slice(-6).map((m) => ({
        role: m.role,
        content: m.content
      }));

      const res = await api.askCyberQuestion({
        question: q,
        attack_type: 'General',
        context: {},
        conversation_history: turns
      });

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: res.answer || 'No response returned from AI Gateway.',
        timestamp: new Date().toLocaleTimeString(),
        provider: res.provider || 'AI Gateway',
        model: res.model || 'Universal SOC Model',
        duration_ms: res.duration_ms || 0,
        is_fallback: res.is_fallback || false
      };

      setChatHistory((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      console.error('AI Copilot request error:', err);
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `⚠️ **AI Copilot Notice**: An unexpected communication delay occurred (${err?.message || 'Connection reset'}). Please retry your question.`,
        timestamp: new Date().toLocaleTimeString(),
        provider: 'System Fallback',
        model: 'Offline',
        is_fallback: true
      };
      setChatHistory((prev) => [...prev, errorMsg]);
    } finally {
      setQaLoading(false);
    }
  };

  // Export Transcript
  const handleExport = () => {
    const transcript = chatHistory
      .map((m) => `[${m.timestamp}] ${m.role === 'user' ? 'YOU (ANALYST)' : 'AI COPILOT'}:\n${m.content}\n\n`)
      .join('---\n\n');
    downloadFile(
      transcript,
      `soc-chess-ai-copilot-${Date.now()}.md`,
      'text/markdown;charset=utf-8;'
    );
  };

  // Render markdown formatting with clean code blocks
  const renderFormatted = (text: string) => {
    const parts = text.split(/(```[\s\S]*?```)/g);

    return parts.map((part, index) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const lines = part.slice(3, -3).trim().split('\n');
        const lang = lines[0].trim().toLowerCase();
        const code = (['spl', 'yara', 'bash', 'sh', 'text', 'python', 'powershell', 'json', 'sql', 'javascript', 'ts'].includes(lang)
          ? lines.slice(1)
          : lines
        ).join('\n');
        const blockId = `code-block-${index}`;

        return (
          <div key={index} className="my-3 rounded-xl overflow-hidden border border-cyan-500/30 bg-[#060a12] shadow-xl">
            <div className="flex items-center justify-between px-3.5 py-1.5 bg-slate-900/90 border-b border-white/10 text-xs font-mono">
              <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5" />
                <span>{lang ? lang.toUpperCase() : 'CODE ARTIFACT'}</span>
              </span>
              <button
                onClick={() => copyToClipboard(code, blockId)}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center gap-1 transition-all"
              >
                {copiedKey === blockId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span className="text-[10px]">{copiedKey === blockId ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            <pre className="p-3.5 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
              {code}
            </pre>
          </div>
        );
      }

      // Format headers, bold text, and lists
      const paragraphs = part.split('\n');
      return (
        <div key={index} className="space-y-1.5">
          {paragraphs.map((line, pIdx) => {
            if (line.startsWith('### ')) {
              return (
                <h4 key={pIdx} className="text-sm font-heading font-extrabold text-cyan-300 mt-3 mb-1 flex items-center gap-1.5">
                  {line.replace('### ', '')}
                </h4>
              );
            }
            if (line.startsWith('## ')) {
              return (
                <h3 key={pIdx} className="text-base font-heading font-extrabold text-white mt-4 mb-1.5 border-b border-white/10 pb-1">
                  {line.replace('## ', '')}
                </h3>
              );
            }
            if (line.startsWith('- ') || line.startsWith('* ')) {
              return (
                <div key={pIdx} className="flex items-start gap-2 text-xs font-mono text-slate-200 pl-2">
                  <span className="text-cyan-400 font-bold">•</span>
                  <span>{line.substring(2)}</span>
                </div>
              );
            }
            if (line.trim().length === 0) {
              return <div key={pIdx} className="h-1" />;
            }
            return (
              <p key={pIdx} className="text-xs font-mono text-slate-200 leading-relaxed">
                {line}
              </p>
            );
          })}
        </div>
      );
    });
  };

  // Filtered prompt questions
  const filteredQuestions = quickCategories.flatMap((cat) => {
    if (selectedCategory === 'All' || cat.category.toLowerCase().includes(selectedCategory.toLowerCase())) {
      return cat.questions.map((q: string) => ({ category: cat.category, question: q }));
    }
    return [];
  }).slice(0, 6);

  return (
    <div className="space-y-4 max-w-6xl mx-auto pb-8 font-body">
      
      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* TOP HEADER & STATUS BAR */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/30 p-5 lg:p-6 shadow-[0_0_30px_rgba(99,102,241,0.15)]">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute right-40 bottom-0 w-48 h-48 bg-cyan-500/10 rounded-full blur-2xl pointer-events-none"></div>

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-3 rounded-2xl bg-gradient-to-br from-indigo-500/30 to-cyan-500/20 border border-indigo-500/40 text-cyan-300 shadow-[0_0_20px_rgba(99,102,241,0.3)]">
              <BrainCircuit className="w-7 h-7 animate-pulse text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl lg:text-2xl font-extrabold text-white tracking-wide font-heading">
                  AI Cyber Copilot &amp; Assistant
                </h1>
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 rounded-full">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                  ONLINE
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed mt-0.5">
                Universal AI Assistant for software development, system architecture, and advanced cybersecurity operations.
              </p>
            </div>
          </div>

          {/* Model info & Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-xs font-mono text-slate-300">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>NVIDIA NIM &amp; Multi-Model Engine</span>
            </div>

            <button
              onClick={handleExport}
              disabled={chatHistory.length === 0}
              className="px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-white/10 hover:border-indigo-500/40 transition-all flex items-center gap-1.5 disabled:opacity-40"
              title="Download chat conversation"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>EXPORT</span>
            </button>

            <button
              onClick={() => setChatHistory([])}
              disabled={chatHistory.length === 0}
              className="px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-red-950/40 text-xs font-mono text-slate-300 hover:text-red-300 border border-white/10 hover:border-red-500/40 transition-all flex items-center gap-1.5 disabled:opacity-40"
              title="Clear conversation"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
              <span>CLEAR</span>
            </button>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* QUICK PROMPT CATEGORIES CHIPS */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
          <span className="flex items-center gap-1.5 font-bold uppercase text-indigo-300">
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            <span>Suggested Questions &amp; Prompts</span>
          </span>
          <div className="flex items-center gap-1.5 overflow-x-auto">
            {['All', 'General', 'Coding', 'Attack', 'SIEM', 'Containment'].map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-0.5 rounded-lg text-[10px] font-mono transition-all ${
                  selectedCategory === cat
                    ? 'bg-indigo-600 text-white shadow-[0_0_10px_rgba(99,102,241,0.4)]'
                    : 'bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-white/5'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {filteredQuestions.map((item, idx) => (
            <button
              key={idx}
              onClick={() => handleAsk(item.question)}
              disabled={qaLoading}
              className="text-left p-2.5 rounded-xl bg-slate-900/80 hover:bg-indigo-950/60 border border-white/5 hover:border-indigo-500/40 text-[11px] font-mono text-slate-300 hover:text-indigo-200 transition-all flex items-start justify-between gap-2 group shadow-sm"
            >
              <span className="line-clamp-2">{item.question}</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-indigo-400 shrink-0 mt-0.5" />
            </button>
          ))}
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* MAIN CONVERSATION STREAM */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      <div className="bg-slate-900/90 rounded-2xl border border-white/10 p-4 sm:p-6 backdrop-blur-xl shadow-2xl space-y-4 min-h-[500px] flex flex-col justify-between">
        
        <div className="space-y-4 max-h-[620px] overflow-y-auto pr-1">
          {chatHistory.length === 0 ? (
            <div className="py-20 flex flex-col items-center justify-center text-center space-y-3">
              <div className="p-4 rounded-3xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                <BrainCircuit className="w-12 h-12 text-indigo-400 animate-pulse" />
              </div>
              <h3 className="text-base font-heading font-bold text-white">
                How can I assist you today?
              </h3>
              <p className="text-xs font-mono text-slate-400 max-w-md">
                Ask any question regarding cybersecurity, Python/bash scripting, system architecture, or general technical inquiries.
              </p>
            </div>
          ) : (
            chatHistory.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'} space-y-1.5`}
              >
                {/* Message Header Label */}
                <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400 px-1">
                  {msg.role === 'user' ? (
                    <span className="flex items-center gap-1.5 text-indigo-300 font-bold">
                      <User className="w-3 h-3 text-indigo-400" />
                      <span>YOU (ANALYST) • {msg.timestamp}</span>
                    </span>
                  ) : (
                    <>
                      <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                        <BrainCircuit className="w-3.5 h-3.5 text-cyan-400" />
                        <span>AI COPILOT</span>
                      </span>
                      <span>•</span>
                      <span className="text-slate-400">{msg.model || 'Universal SOC Engine'}</span>
                      {msg.duration_ms ? (
                        <span className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/20">
                          ⚡ {(msg.duration_ms / 1000).toFixed(2)}s
                        </span>
                      ) : null}
                    </>
                  )}
                </div>

                {/* Message Bubble Body */}
                <div
                  className={`p-4 rounded-2xl max-w-3xl text-xs font-mono transition-all ${
                    msg.role === 'user'
                      ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white rounded-tr-none shadow-[0_0_15px_rgba(99,102,241,0.25)]'
                      : 'bg-slate-950/90 border border-indigo-500/30 text-slate-200 rounded-tl-none shadow-xl'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  ) : (
                    <div className="space-y-2">
                      {renderFormatted(msg.content)}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}

          {/* Reasoning / Thinking State */}
          {qaLoading && (
            <div className="flex items-start gap-3 p-4 rounded-2xl bg-slate-950/90 border border-indigo-500/30 max-w-xl text-xs font-mono text-indigo-300">
              <BrainCircuit className="w-5 h-5 text-indigo-400 animate-spin shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="font-bold flex items-center gap-2">
                  <span>AI Copilot is analyzing &amp; synthesizing your answer...</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  Processing via NVIDIA NIM Multi-Model Gateway &amp; Cybersecurity Knowledge Base...
                </div>
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        {/* ═══════════════════════════════════════════════════════════════ */}
        {/* INPUT CONSOLE BAR */}
        {/* ═══════════════════════════════════════════════════════════════ */}
        <div className="pt-2 border-t border-white/5 space-y-2">
          <div className="flex items-center gap-3 p-2 bg-slate-950 border border-indigo-500/40 rounded-2xl shadow-[0_0_20px_rgba(99,102,241,0.15)] focus-within:border-cyan-400 focus-within:ring-1 focus-within:ring-cyan-500/30 transition-all">
            <textarea
              ref={inputRef}
              rows={1}
              value={questionInput}
              onChange={(e) => setQuestionInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleAsk();
                }
              }}
              disabled={qaLoading}
              placeholder="Ask anything (e.g. 'Explain Zero Trust', 'Write a Python port scanner', 'What is SQL Injection?')..."
              className="flex-1 bg-transparent px-3 py-2 text-xs font-mono text-white placeholder-slate-500 outline-none resize-none max-h-32"
            />

            <button
              onClick={() => handleAsk()}
              disabled={!questionInput.trim() || qaLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:from-indigo-500 hover:to-cyan-400 text-xs font-heading font-bold text-white flex items-center gap-2 shadow-[0_0_15px_rgba(99,102,241,0.3)] transition-all disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{qaLoading ? 'ANALYZING...' : 'SEND'}</span>
            </button>
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 px-1">
            <span>Press <strong>Enter</strong> to send • <strong>Shift+Enter</strong> for newline</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-emerald-400" />
              <span>Universal AI &amp; Cybersecurity Assistance Active</span>
            </span>
          </div>
        </div>

      </div>

    </div>
  );
};
