import {
  ActionIcon,
  Alert,
  Code,
  Group,
  MultiSelect,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconCopy } from "@tabler/icons-react";
import { allScopes, scopeNames, showError, success } from "./api";
import { copyText } from "./list-export";
import {
  type McpOAuth,
  mcpMetadataURL,
  mcpResourceURL,
} from "./mcp-oauth-state";
const scopeOptions = allScopes.map((s) => ({
  value: s,
  label: `${scopeNames[s]} · ${s}`,
}));

function CopyLine({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Text size="sm" fw={500}>
        {label}
      </Text>
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <Code
          block
          style={{ flex: 1, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
        >
          {value}
        </Code>
        <Tooltip label="복사">
          <ActionIcon
            variant="light"
            aria-label={`${label} 복사`}
            onClick={async () => {
              try {
                await copyText(value);
                success(`${label}를 복사했습니다`);
              } catch {
                showError(
                  new Error(
                    "브라우저의 복사 권한을 확인하거나 주소를 직접 선택해 복사하세요.",
                  ),
                );
              }
            }}
          >
            <IconCopy size={16} />
          </ActionIcon>
        </Tooltip>
      </Group>
    </div>
  );
}

// The resource-server half of MCP authorization: where Keycloak is, which
// tokens are for this server, and how far an SSO subject may go. Hunter never
// issues tokens; the web sign-in (SSO · 로그인 group) must already work.
export function McpOAuthSettings({
  value,
  onChange,
  publicURL,
  oidcEnabled,
}: {
  value: McpOAuth;
  onChange: (next: McpOAuth) => void;
  publicURL: string;
  oidcEnabled: boolean;
}) {
  const resource = mcpResourceURL(publicURL, value.resource);
  return (
    <Stack gap="md">
      <Text size="sm">
        개인 키 대신 Keycloak(사내 SSO) 액세스 토큰으로 <Code>/mcp</Code> 에
        연결하게 합니다. 키 체계는 그대로 유지되고, 토큰은 <Code>/mcp</Code> 에서만
        받으며, 웹으로 한 번 로그인해 등록된 활성 계정만 통과합니다. 켜려면 SSO ·
        로그인 그룹의 OIDC 가 먼저 저장돼 있어야 합니다.
      </Text>
      {!oidcEnabled && (
        <Alert color="yellow" title="OIDC SSO 로그인이 꺼져 있습니다">
          SSO · 로그인 그룹에서 OIDC 를 켜고 Issuer URL 을 저장한 뒤 이 스위치를
          켤 수 있습니다.
        </Alert>
      )}
      <Switch
        id="settings-mcp-oauth-enabled"
        label="SSO 액세스 토큰으로 MCP 연결 허용"
        description="기본 꺼짐입니다. 끄면 메타데이터가 404 로 돌아가고 토큰은 키 전용일 때와 똑같이 거부됩니다."
        checked={value.enabled}
        onChange={(e) => onChange({ ...value, enabled: e.currentTarget.checked })}
      />
      <TextInput
        id="settings-mcp-oauth-resource"
        label="리소스 식별자"
        placeholder={`${publicURL.replace(/\/+$/, "")}/mcp`}
        description="토큰의 aud 가 가리켜야 하는 이 서버의 공개 MCP 주소입니다. 비우면 서비스 외부 접근 주소 + /mcp 를 씁니다. 프록시 뒤 내부 주소가 아니라 클라이언트가 실제로 접속하는 HTTPS 주소여야 합니다."
        value={value.resource}
        onChange={(e) => onChange({ ...value, resource: e.currentTarget.value })}
      />
      <TagsInput
        id="settings-mcp-oauth-audience"
        label="허용 대상 (aud 또는 azp)"
        description="Audience 매퍼 없이 쓰는 호환 경로입니다. Keycloak 26 은 클라이언트 ID 를 azp 에 담으므로 MCP 클라이언트 ID(예: claude-mcp)를 적으면 됩니다. 웹 로그인 Client ID 는 항상 허용됩니다."
        placeholder="claude-mcp"
        value={value.audience}
        onChange={(audience) => onChange({ ...value, audience })}
        splitChars={[" ", ",", "\n"]}
        maxTags={20}
      />
      <MultiSelect
        id="settings-mcp-oauth-scopes"
        label="SSO 토큰 주체에게 주는 권한"
        description="토큰의 scope 가 아니라 이 목록이 상한입니다. 실제 권한은 이 목록과 사용자 역할 권한의 교집합이며, 교집합이 비면 연결이 거부됩니다."
        data={scopeOptions}
        value={value.scopes}
        onChange={(scopes) => onChange({ ...value, scopes })}
        searchable
        required={value.enabled}
      />
      <Alert color="teal" title="클라이언트에 알려 줄 값">
        <Stack gap="sm">
          <Text size="sm">
            MCP 클라이언트(Claude, Cursor 등)에는 MCP 주소 하나만 주면 됩니다.
            401 응답의 <Code>WWW-Authenticate</Code> 가 메타데이터 주소를
            가리키고, 클라이언트가 Keycloak 으로 로그인해 토큰을 받아 옵니다.
          </Text>
          <CopyLine label="MCP 주소 (리소스 식별자)" value={resource} />
          <CopyLine
            label="보호 리소스 메타데이터 주소"
            value={mcpMetadataURL(publicURL)}
          />
          <Text size="sm">
            Keycloak 에는 웹 로그인과 <strong>다른</strong> 공개(public)
            클라이언트를 만들고(Standard Flow, PKCE S256, 콜백 주소를 정확히
            등록), 정식 경로로는 그 클라이언트에 Audience 매퍼(Included Custom
            Audience = 위 MCP 주소, access token 에만)를 두거나 호환 경로로는 그
            클라이언트 ID 를 위 허용 대상에 적습니다. 자세한 순서는 관리자
            가이드 §15.6 에 있습니다.
          </Text>
        </Stack>
      </Alert>
    </Stack>
  );
}
