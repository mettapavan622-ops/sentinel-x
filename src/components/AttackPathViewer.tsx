import React from 'react';
import {
  Key,
  Shield,
  Cloud,
  Database,
  Skull,
  ArrowRight,
  AlertTriangle,
  Flame,
} from 'lucide-react';
import { AttackPath, AttackNode } from '../types';

interface AttackPathViewerProps {
  attackPath: AttackPath;
}

export const AttackPathViewer: React.FC<AttackPathViewerProps> = ({ attackPath }) => {
  const getNodeIcon = (type: AttackNode['type']) => {
    switch (type) {
      case 'CREDENTIAL':
        return <Key className="w-5 h-5 text-rose-400" />;
      case 'IAM_IDENTITY':
        return <Shield className="w-5 h-5 text-amber-400" />;
      case 'CLOUD_SERVICE':
        return <Cloud className="w-5 h-5 text-cyan-400" />;
      case 'DATA_STORE':
        return <Database className="w-5 h-5 text-indigo-400" />;
      case 'IMPACT':
        return <Skull className="w-5 h-5 text-rose-500" />;
      default:
        return <AlertTriangle className="w-5 h-5 text-slate-400" />;
    }
  };

  const getRiskBorder = (risk: AttackNode['risk']) => {
    switch (risk) {
      case 'CRITICAL':
        return 'border-rose-500/40 bg-rose-950/20';
      case 'HIGH':
        return 'border-amber-500/40 bg-amber-950/20';
      default:
        return 'border-cyan-500/40 bg-cyan-950/20';
    }
  };

  return (
    <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>Threat Model & Attack-Path Trace</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
              Blast Radius: {attackPath.estimatedBlastRadius}
            </span>
          </h4>
          <p className="text-xs text-slate-400 mt-0.5 max-w-2xl">{attackPath.summary}</p>
        </div>
      </div>

      {/* Attack Graph Node Sequence */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-3 overflow-x-auto py-2">
        {attackPath.nodes.map((node, index) => {
          const edge = attackPath.edges[index];

          return (
            <React.Fragment key={node.id}>
              {/* Node Card */}
              <div
                className={`flex-1 min-w-[200px] border rounded-lg p-3.5 flex flex-col justify-between ${getRiskBorder(
                  node.risk
                )}`}
              >
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="p-1.5 rounded-md bg-slate-900 border border-slate-800">
                    {getNodeIcon(node.type)}
                  </div>
                  <span className="text-[10px] font-mono font-bold text-slate-400">
                    {node.type}
                  </span>
                </div>
                <div>
                  <div className="text-xs font-bold text-slate-100">{node.label}</div>
                  <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                    {node.description}
                  </div>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-500">Node Risk:</span>
                  <span
                    className={
                      node.risk === 'CRITICAL'
                        ? 'text-rose-400 font-bold'
                        : node.risk === 'HIGH'
                        ? 'text-amber-400 font-semibold'
                        : 'text-cyan-400'
                    }
                  >
                    {node.risk}
                  </span>
                </div>
              </div>

              {/* Edge Transition Arrow */}
              {index < attackPath.nodes.length - 1 && (
                <div className="flex lg:flex-col items-center justify-center text-slate-500 py-1 lg:py-0 px-2">
                  <ArrowRight className="w-4 h-4 text-cyan-500/70" />
                  {edge && (
                    <span className="text-[9px] font-mono text-slate-400 ml-2 lg:ml-0 lg:mt-1 text-center max-w-[100px] hidden xl:block">
                      {edge.reason.slice(0, 30)}...
                    </span>
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
