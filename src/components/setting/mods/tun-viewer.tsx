import { forwardRef, useImperativeHandle, useState } from "react";
import { useLockFn } from "ahooks";
import { useTranslation } from "react-i18next";
import {
  Chip,
  Divider,
  List,
  ListItem,
  ListItemText,
  Box,
  Typography,
  Button,
  TextField,
  Stack,
} from "@mui/material";
import { LoadingButton } from "@mui/lab";
import { useClash } from "@/hooks/use-clash";
import { BaseDialog, DialogRef, Notice, Switch } from "@/components/base";
import { StackModeSwitch } from "./stack-mode-switch";
import { diagnoseTunOutbound } from "@/services/cmds";

interface TunDiagResult {
  reasons?: string[];
  tun_enabled?: boolean;
  service_core_managed?: boolean;
  core_api_ready?: boolean;
  dns_hijack_ok?: boolean;
  route_injected?: boolean;
  mode?: string;
  selected_proxy?: string;
  selected_proxy_reachable?: boolean;
  multiple_tun_adapters_detected?: boolean;
  adapter_candidates?: string[];
  service_log_file?: string;
  service_log_summary?: string[];
}

export const TunViewer = forwardRef<DialogRef>((props, ref) => {
  const { t } = useTranslation();

  const { clash, mutateClash, patchClash } = useClash();

  const [open, setOpen] = useState(false);
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagResult, setDiagResult] = useState<TunDiagResult | null>(null);
  const [values, setValues] = useState({
    stack: "gvisor",
    device: "Clash-Verge-Buty",
    autoRoute: true,
    autoDetectInterface: true,
    dnsHijack: ["any:53", "tcp://any:53"],
    strictRoute: false,
    mtu: 9000,
  });

  useImperativeHandle(ref, () => ({
    open: () => {
      setOpen(true);
      setValues({
        stack: clash?.tun.stack ?? "gvisor",
        device: clash?.tun.device ?? "Clash-Verge-Buty",
        autoRoute: clash?.tun["auto-route"] ?? true,
        autoDetectInterface: clash?.tun["auto-detect-interface"] ?? true,
        dnsHijack: clash?.tun["dns-hijack"] ?? ["any:53", "tcp://any:53"],
        strictRoute: clash?.tun["strict-route"] ?? false,
        mtu: clash?.tun.mtu ?? 9000,
      });
    },
    close: () => setOpen(false),
  }));

  const onSave = useLockFn(async () => {
    try {
      const dnsHijack = values.dnsHijack
        .map((item) => item.trim())
        .filter(Boolean);
      let tun = {
        stack: values.stack.toLowerCase(),
        device: values.device.trim() || "Clash-Verge-Buty",
        "auto-route": values.autoRoute,
        "auto-detect-interface": values.autoDetectInterface,
        "dns-hijack": dnsHijack.length ? dnsHijack : ["any:53", "tcp://any:53"],
        "strict-route": values.strictRoute,
        mtu: Number.isFinite(values.mtu) && values.mtu > 0 ? values.mtu : 9000,
      };
      await patchClash({ tun });
      await mutateClash(
        (old) => ({
          ...(old! || {}),
          tun,
        }),
        false
      );
      setOpen(false);
    } catch (err: any) {
      Notice.error(err.message || err.toString());
    }
  });

  const onDiagnose = useLockFn(async () => {
    try {
      setDiagLoading(true);
      const res = await diagnoseTunOutbound();
      setDiagResult(res || {});
      setDiagOpen(true);
    } catch (err: any) {
      Notice.error(err?.message || err?.toString?.() || "diagnose failed");
    } finally {
      setDiagLoading(false);
    }
  });

  const reasons = diagResult?.reasons || [];
  const hasProxyUnavailable = reasons.some((r) =>
    r.toLowerCase().includes("selected proxy")
  );
  const hasMultiAdapter = reasons.some((r) =>
    r.toLowerCase().includes("multiple tun adapters")
  );
  const hasOutboundLogHint = reasons.some(
    (r) =>
      r.toLowerCase().includes("outbound failed") ||
      r.toLowerCase().includes("service log")
  );

  return (
    <BaseDialog
      open={open}
      title={
        <Box display="flex" justifyContent="space-between" gap={1}>
          <Typography variant="h6">{t("Tun Mode")}</Typography>
          <Button
            variant="outlined"
            size="small"
            onClick={async () => {
              let tun = {
                stack: "gvisor",
                device: "Clash-Verge-Buty",
                "auto-route": true,
                "auto-detect-interface": true,
                "dns-hijack": ["any:53", "tcp://any:53"],
                "strict-route": false,
                mtu: 9000,
              };
              setValues({
                stack: "gvisor",
                device: "Clash-Verge-Buty",
                autoRoute: true,
                autoDetectInterface: true,
                dnsHijack: ["any:53", "tcp://any:53"],
                strictRoute: false,
                mtu: 9000,
              });
              await patchClash({ tun });
              await mutateClash(
                (old) => ({
                  ...(old! || {}),
                  tun,
                }),
                false
              );
            }}
          >
            {t("Reset to Default")}
          </Button>
        </Box>
      }
      contentSx={{ width: 450 }}
      okBtn={t("Save")}
      cancelBtn={t("Cancel")}
      onClose={() => setOpen(false)}
      onCancel={() => setOpen(false)}
      onOk={onSave}
    >
      <List>
        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("Stack")} />
          <StackModeSwitch
            value={values.stack}
            onChange={(value) => {
              setValues((v) => ({
                ...v,
                stack: value,
              }));
            }}
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("Device")} />
          <TextField
            size="small"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.device}
            placeholder="Clash-Verge-Buty"
            onChange={(e) =>
              setValues((v) => ({ ...v, device: e.target.value }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("Auto Route")} />
          <Switch
            edge="end"
            checked={values.autoRoute}
            onChange={(_, c) => setValues((v) => ({ ...v, autoRoute: c }))}
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("Strict Route")} />
          <Switch
            edge="end"
            checked={values.strictRoute}
            onChange={(_, c) => setValues((v) => ({ ...v, strictRoute: c }))}
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("Auto Detect Interface")} />
          <Switch
            edge="end"
            checked={values.autoDetectInterface}
            onChange={(_, c) =>
              setValues((v) => ({ ...v, autoDetectInterface: c }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("DNS Hijack")} />
          <TextField
            size="small"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.dnsHijack.join(",")}
            placeholder="Please use , to separate multiple DNS servers"
            onChange={(e) =>
              setValues((v) => ({
                ...v,
                dnsHijack: e.target.value.split(",").map((item) => item.trim()),
              }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: "5px 2px" }}>
          <ListItemText primary={t("MTU")} />
          <TextField
            size="small"
            type="number"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck="false"
            sx={{ width: 250 }}
            value={values.mtu}
            placeholder="9000"
            onChange={(e) =>
              setValues((v) => ({
                ...v,
                mtu: parseInt(e.target.value),
              }))
            }
          />
        </ListItem>

        <ListItem sx={{ padding: "10px 2px 0 2px" }}>
          <Box width="100%" display="flex" justifyContent="flex-end">
            <LoadingButton
              loading={diagLoading}
              variant="outlined"
              onClick={onDiagnose}
            >
              诊断 TUN 出站
            </LoadingButton>
          </Box>
        </ListItem>
      </List>

      <BaseDialog
        open={diagOpen}
        title={<Typography variant="h6">TUN 出站诊断结果</Typography>}
        onClose={() => setDiagOpen(false)}
        onCancel={() => setDiagOpen(false)}
        disableOk
        cancelBtn={t("Close")}
        contentSx={{ width: 620 }}
      >
        <Stack spacing={1}>
          <Typography fontWeight={700}>基础状态</Typography>
          <Typography variant="body2">
            Service/Core ownership: {String(diagResult?.service_core_managed)}
          </Typography>
          <Typography variant="body2">
            Core API ready: {String(diagResult?.core_api_ready)}
          </Typography>
          <Typography variant="body2">
            TUN enable: {String(diagResult?.tun_enabled)}
          </Typography>
          <Typography variant="body2">Mode: {diagResult?.mode || "-"}</Typography>

          <Divider />
          <Typography fontWeight={700}>网络状态</Typography>
          <Typography variant="body2">
            DNS hijack working: {String(diagResult?.dns_hijack_ok)}
          </Typography>
          <Typography variant="body2">
            Route injected: {String(diagResult?.route_injected)}
          </Typography>
          <Typography variant="body2">
            Selected proxy: {diagResult?.selected_proxy || "-"}
          </Typography>
          <Typography variant="body2">
            Selected proxy reachable:{" "}
            {String(diagResult?.selected_proxy_reachable)}
          </Typography>

          <Divider />
          <Typography fontWeight={700}>风险提示</Typography>
          {reasons.length === 0 ? (
            <Typography variant="body2" color="success.main">
              TUN diagnostic passed. If web access still fails, check
              browser/app-specific proxy or firewall rules.
              <br />
              TUN 诊断未发现明显异常。如果仍无法联网，请检查浏览器/应用自身代理设置、防火墙或当前节点连通性。
            </Typography>
          ) : (
            <Box display="flex" flexWrap="wrap" gap={1}>
              {reasons.map((item, idx) => (
                <Chip key={`${item}-${idx}`} label={item} size="small" />
              ))}
            </Box>
          )}

          {hasProxyUnavailable && (
            <Typography variant="body2" color="warning.main">
              TUN 已启用，但当前选中代理节点不可用，请切换节点或检查代理组选择。
            </Typography>
          )}
          {hasMultiAdapter && (
            <Typography variant="body2" color="warning.main">
              检测到多个 TUN/Wintun/Meta 相关网卡，可能存在旧 TUN 残留冲突。请检查
              vgate0、Rust Wintun Tunnel、Meta Tunnel 等适配器。
            </Typography>
          )}
          <Typography variant="body2">
            Multiple TUN adapters:{" "}
            {String(diagResult?.multiple_tun_adapters_detected)}
          </Typography>
          <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
            Candidate adapters: {(diagResult?.adapter_candidates || []).join(" | ") || "-"}
          </Typography>

          {hasOutboundLogHint && (
            <>
              <Divider />
              <Typography fontWeight={700}>日志摘要</Typography>
              <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
                Service log file: {diagResult?.service_log_file || "-"}
              </Typography>
              <Box
                sx={{
                  maxHeight: 180,
                  overflow: "auto",
                  bgcolor: "background.default",
                  borderRadius: 1,
                  p: 1,
                  fontFamily: "monospace",
                  fontSize: 12,
                }}
              >
                {(diagResult?.service_log_summary || []).length ? (
                  (diagResult?.service_log_summary || []).map((line, idx) => (
                    <Typography key={idx} variant="caption" display="block">
                      {line}
                    </Typography>
                  ))
                ) : (
                  <Typography variant="caption">No matched log summary.</Typography>
                )}
              </Box>
            </>
          )}
        </Stack>
      </BaseDialog>
    </BaseDialog>
  );
});
