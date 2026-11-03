import { useState } from 'react';
import { toast } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { Loader2, AlertTriangle } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { useTranslation } from 'react-i18next';
import type { Rule } from '@/bridge/types';
import { RULE_TYPE_NAME } from '@/components/rules/rule-type-meta';

interface DeleteRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule: Rule;
}

/** 规则 action → Conduit pill 配色 class（代理主色 / 直连中性 / 阻断危险红）。 */
function actionPillClass(action: string): string {
  const a = (action || '').toLowerCase();
  if (a === 'direct') return 'rl-direct';
  if (a === 'block' || a === 'reject' || a === 'reject-drop' || a === 'drop') return 'rl-block';
  return 'rl-proxy';
}

export function DeleteRuleDialog({ open, onOpenChange, rule }: DeleteRuleDialogProps) {
  const { t } = useTranslation();
  const deleteCustomRule = useAppStore((state) => state.deleteCustomRule);
  const [isDeleting, setIsDeleting] = useState(false);

  const handleDelete = async () => {
    if (!rule.id) {
      toast.error(t('rules.deleteFailed', 'Delete failed'), {
        description: t('rules.invalidRuleId', 'Invalid rule ID'),
      });
      return;
    }

    setIsDeleting(true);
    try {
      await deleteCustomRule(rule.id);
      toast.success(t('rules.ruleDeleted', 'Rule deleted'));
      onOpenChange(false);
    } catch (error) {
      console.error('Failed to delete rule:', error);
      toast.error(t('rules.deleteFailed', 'Delete failed'), {
        description:
          error instanceof Error
            ? error.message
            : t('rules.deleteErrorDesc', 'An error occurred while deleting the rule'),
      });
    } finally {
      setIsDeleting(false);
    }
  };

  const actionLabel =
    rule.action === 'proxy'
      ? t('rules.policyProxy', 'Proxy')
      : rule.action === 'direct'
        ? t('rules.policyDirect', 'Direct')
        : t('rules.policyBlock', 'Block');

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[92vh] max-w-[425px] flex-col gap-0 overflow-hidden p-0">
        <div className="rl-dlg-h">
          <div>
            <DialogTitle
              className="rl-dlg-title"
              style={{ display: 'flex', alignItems: 'center', gap: 8 }}
            >
              <AlertTriangle size={18} style={{ color: 'hsl(var(--err))' }} />
              {t('rules.deleteRule', 'Delete Rule')}
            </DialogTitle>
            <DialogDescription className="rl-dlg-desc">
              {t('rules.deleteConfirm', 'This action cannot be undone. Delete this rule?')}
            </DialogDescription>
          </div>
        </div>

        <div className="rl-dlg-body min-h-0 flex-1 overflow-y-auto">
          <div className="rl-zone">
            <div className="rl-optcard" style={{ padding: '12px 14px', display: 'grid', gap: 10 }}>
              <div
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
              >
                <span className="rl-hc-lbl">{t('rules.typeColumn', 'Type')}</span>
                <span className="pill rl-cond">
                  {t(`rules.types.${rule.type}.name`, RULE_TYPE_NAME[rule.type])}
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="rl-hc-lbl">{t('rules.valueLabel', 'Match values')}</span>
                <div className="mono" style={{ maxHeight: 120, overflowY: 'auto', fontSize: 12 }}>
                  {rule.values.map((value, index) => (
                    <div key={index}>{value}</div>
                  ))}
                </div>
              </div>
              <div
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
              >
                <span className="rl-hc-lbl">{t('rules.policy', 'Policy')}</span>
                <span className={`pill ${actionPillClass(rule.action)}`}>{actionLabel}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="rl-dlg-foot">
          <button
            type="button"
            className="btn ghost"
            onClick={() => onOpenChange(false)}
            disabled={isDeleting}
          >
            {t('servers.cancel', 'Cancel')}
          </button>
          <button type="button" className="btn danger" onClick={handleDelete} disabled={isDeleting}>
            {isDeleting && <Loader2 className="animate-spin" size={15} />}
            {t('rules.delete', 'Delete')}
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
