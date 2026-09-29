import React, { useState, useRef, useEffect } from 'react';
import {
  X,
  Send,
  Cpu,
  User,
  Bot,
  Sparkles,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import { ChatMessage, Finding } from '../types';

interface AIAssistantDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  securityScore: number;
  findings: Finding[];
}

export const AIAssistantDrawer: React.FC<AIAssistantDrawerProps> = ({
  isOpen,
  onClose,
  securityScore,
  findings,
}) => {
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>(() => [
    {
      id: 'msg-init-01',
      conversationId: 'conv-default-01',
      role: 'assistant',
      content: `### 👋 Greetings! I am SENTINEL-X AI Security Assistant

I have deep contextual awareness of your repository and active findings. Current Repository Health Score: **${securityScore}/100**.

You can ask me to:
- Explain specific threat models or attack paths
- Guide credential rotation protocols
- Clarify why documentation tokens were dismissed as false positives
- Generate custom remediation workflows`,
      createdAt: new Date().toISOString(),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  if (!isOpen) return null;

  const handleSend = async (textToSend?: string) => {
    const q = textToSend || inputQuery;
    if (!q.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}-u`,
      conversationId: 'conv-default-01',
      role: 'user',
      content: q,
      createdAt: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          conversationId: 'conv-default-01',
          message: q,
        }),
      });
      const data = await res.json();
      if (data.assistantMessage) {
        setMessages((prev) => [...prev, data.assistantMessage]);
      }
    } catch (err) {
      console.error('Failed to query assistant:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const suggestionChips = [
    'Why is the AWS finding critical?',
    'How do I fix the Stripe secret?',
    'Explain the false positive in docs',
    'What is the blast radius of the database leak?',
  ];

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col">
      {/* Drawer Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              <span>SENTINEL-X AI Assistant</span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-1.5 py-0.2 rounded border border-cyan-800">
                Grounded
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">Contextual secret threat intelligence</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Suggestion Chips */}
      <div className="p-3 border-b border-slate-800/80 bg-slate-950/40 flex items-center gap-1.5 overflow-x-auto text-[11px] font-mono text-slate-400">
        <span className="text-slate-500 flex-shrink-0">Prompts:</span>
        {suggestionChips.map((chip, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(chip)}
            className="flex-shrink-0 px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-700/60 transition-colors"
          >
            {chip}
          </button>
        ))}
      </div>

      {/* Message Stream */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4 font-sans text-xs">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex items-start gap-2.5 ${
              msg.role === 'user' ? 'flex-row-reverse' : ''
            }`}
          >
            <div
              className={`p-1.5 rounded-md flex-shrink-0 ${
                msg.role === 'user'
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-800 border border-slate-700 text-cyan-400'
              }`}
            >
              {msg.role === 'user' ? <User className="w-3.5 h-3.5" /> : <Bot className="w-3.5 h-3.5" />}
            </div>

            <div
              className={`rounded-xl p-3 max-w-[85%] leading-relaxed ${
                msg.role === 'user'
                  ? 'bg-cyan-600 text-white font-medium'
                  : 'bg-slate-950 border border-slate-800 text-slate-200'
              }`}
            >
              <div className="whitespace-pre-wrap">{msg.content}</div>
              <div className="mt-1 text-[9px] text-slate-400 text-right">
                {new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </div>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs italic">
            <Bot className="w-3.5 h-3.5 animate-spin text-cyan-400" />
            <span>Analyzing repository security context...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <div className="p-3 border-t border-slate-800 bg-slate-950">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            id="input-chat-query"
            type="text"
            placeholder="Ask about findings, rotation, attack paths..."
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            className="flex-1 px-3 py-2 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            id="btn-send-chat"
            type="submit"
            disabled={!inputQuery.trim() || isLoading}
            className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
