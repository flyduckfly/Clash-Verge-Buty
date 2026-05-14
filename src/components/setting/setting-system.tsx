import useSWR from "swr";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { IconButton, Tooltip } from "@mui/material";
import { PrivacyTipRounded, Settings, InfoRounded } from "@mui/icons-material";
import {
  checkService,
  getCurrentLogFilePath,
  getDebugRecordingStatus,
  openLogsDir,
  startDebugRecording,
  stopDebugRecording,
} from "@/services/cmds";
import { useVerge } from "@/hooks/use-verge";
import { DialogRef, Switch } from "@/components/base";
import { SettingList, SettingItem } from "./mods/setting-comp";
import { GuardState } from "./mods/guard-state";
import { ServiceViewer } from "./mods/service-viewer";
import { SysproxyViewer } from "./mods/sysproxy-viewer";
import { TunViewer } from "./mods/tun-viewer";
import getSystem from "@/utils/get-system";

interface Props {
  onError?: (err: Error) => void;
}

const isWIN = getSystem() === "windows";

const SettingSystem = ({ onError }: Props) => {
  const { t } = useTranslation();

  const { verge, mutateVerge, patchVerge } = useVerge();

  // service mode
  const { data: serviceStatus } = useSWR(
    isWIN ? "checkService" : null,
    checkService,
    {
      revalidateIfStale: false,
      shouldRetryOnError: false,
      focusThrottleInterval: 5000, // 5s
    }
  );

  const serviceRef = useRef<DialogRef>(null);
  const sysproxyRef = useRef<DialogRef>(null);
  const tunRef = useRef<DialogRef>(null);

  const {
    enable_tun_mode,
    enable_auto_launch,
    enable_service_mode,
    enable_silent_start,
    enable_system_proxy,
  } = verge ?? {};

  const onSwitchFormat = (_e: any, value: boolean) => value;
  const onChangeData = (patch: Partial<IVergeConfig>) => {
    mutateVerge({ ...verge, ...patch }, false);
  };
  const [debugRecording, setDebugRecording] = useState(false);
  const [debugPath, setDebugPath] = useState("");
  const [logPath, setLogPath] = useState("");
  const [debugLoading, setDebugLoading] = useState(false);

  useEffect(() => {
    getDebugRecordingStatus().then((s) => {
      setDebugRecording(!!s.recording);
      setDebugPath(s.path || "");
    });
    getCurrentLogFilePath().then(setLogPath).catch(() => setLogPath("unknown"));
  }, []);

  return (
    <SettingList title={t("System Setting")}>
      <SysproxyViewer ref={sysproxyRef} />
      <TunViewer ref={tunRef} />
      {isWIN && (
        <ServiceViewer ref={serviceRef} enable={!!enable_service_mode} />
      )}

      <SettingItem
        label={t("Tun Mode")}
        extra={
          <>
            <Tooltip
              title={
                isWIN ? t("Tun Mode Info Windows") : t("Tun Mode Info Unix")
              }
              placement="top"
            >
              <IconButton color="inherit" size="small">
                <InfoRounded
                  fontSize="inherit"
                  style={{ cursor: "pointer", opacity: 0.75 }}
                />
              </IconButton>
            </Tooltip>
            <IconButton
              color="inherit"
              size="small"
              onClick={() => tunRef.current?.open()}
            >
              <Settings
                fontSize="inherit"
                style={{ cursor: "pointer", opacity: 0.75 }}
              />
            </IconButton>
          </>
        }
      >
        <GuardState
          value={enable_tun_mode ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_tun_mode: e })}
          onGuard={(e) => patchVerge({ enable_tun_mode: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      {isWIN && (
        <SettingItem
          label={t("Service Mode")}
          extra={
            <IconButton
              color="inherit"
              size="small"
              onClick={() => serviceRef.current?.open()}
            >
              <PrivacyTipRounded
                fontSize="inherit"
                style={{ cursor: "pointer", opacity: 0.75 }}
              />
            </IconButton>
          }
        >
          <GuardState
            value={enable_service_mode ?? false}
            valueProps="checked"
            onCatch={onError}
            onFormat={onSwitchFormat}
            onChange={(e) => onChangeData({ enable_service_mode: e })}
            onGuard={(e) => patchVerge({ enable_service_mode: e })}
          >
            <Switch
              edge="end"
              disabled={serviceStatus ? !serviceStatus.installed : false}
            />
          </GuardState>
        </SettingItem>
      )}

      <SettingItem
        label={t("System Proxy")}
        extra={
          <IconButton
            color="inherit"
            size="small"
            onClick={() => sysproxyRef.current?.open()}
          >
            <Settings
              fontSize="inherit"
              style={{ cursor: "pointer", opacity: 0.75 }}
            />
          </IconButton>
        }
      >
        <GuardState
          value={enable_system_proxy ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_system_proxy: e })}
          onGuard={(e) => patchVerge({ enable_system_proxy: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem label={t("Auto Launch")}>
        <GuardState
          value={enable_auto_launch ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_auto_launch: e })}
          onGuard={(e) => patchVerge({ enable_auto_launch: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem label="Debug Recording">
        <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
          <div style={{ fontSize: 12, opacity: 0.8 }}>status: {debugRecording ? "recording" : "stopped"}</div>
          <div style={{ fontSize: 12, maxWidth: 340, textAlign: "right", wordBreak: "break-all" }}>debug: {debugPath || "-"}</div>
          <div style={{ fontSize: 12, maxWidth: 340, textAlign: "right", wordBreak: "break-all" }}>source: {logPath || "-"}</div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              disabled={debugLoading}
              onClick={async () => {
                setDebugLoading(true);
                try {
                  const r = await startDebugRecording();
                  setDebugRecording(true);
                  setDebugPath(r.path || "");
                } catch (e: any) {
                  onError?.(e);
                } finally {
                  setDebugLoading(false);
                }
              }}
            >
              开始记录调试日志
            </button>
            <button
              disabled={debugLoading}
              onClick={async () => {
                setDebugLoading(true);
                try {
                  const r = await stopDebugRecording();
                  setDebugRecording(false);
                  setDebugPath(r.path || "");
                } catch (e: any) {
                  onError?.(e);
                } finally {
                  setDebugLoading(false);
                }
              }}
            >
              停止记录调试日志
            </button>
            <button onClick={openLogsDir}>打开日志目录</button>
          </div>
        </div>
      </SettingItem>

      <SettingItem label={t("Silent Start")}>
        <GuardState
          value={enable_silent_start ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_silent_start: e })}
          onGuard={(e) => patchVerge({ enable_silent_start: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>
    </SettingList>
  );
};

export default SettingSystem;
