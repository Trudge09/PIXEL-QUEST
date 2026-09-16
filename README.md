# PIXEL QUEST Google 로그인 + D1 동기화

## 배포 전 필수 작업

1. Cloudflare → Workers & Pages → `pixel-quest` → Settings → Variables and Secrets에서 **Secret** `SESSION_SECRET`을 생성하세요. 최소 32바이트의 암호학적으로 안전한 무작위 문자열을 사용하고 GitHub/HTML/채팅에 공개하지 마세요. 기존 `DB` 바인딩은 Wrangler 설정에 포함되어 있습니다.
2. Google Cloud OAuth 웹 클라이언트의 **승인된 JavaScript 원본**에 `https://pixel-quest.seewhyz.workers.dev`를 추가하세요. 끝의 `/`는 넣지 마세요. OAuth 동의 화면이 테스트 모드라면 로그인할 Google 계정을 테스트 사용자로 추가하세요.
3. GitHub `Trudge09/PIXEL-QUEST` 저장소에서 루트의 `index.html`을 `public/index.html`로 이동하고, 이 패키지의 `public/index.html`, `worker.js`, `wrangler.jsonc`를 같은 경로에 업로드하세요. 루트 `index.html`은 삭제해야 합니다. **파일을 하나씩 커밋하면 중간 상태가 자동 배포될 수 있으니 가능하면 한 커밋으로 올리세요.** `wrangler.jsonc`의 `assets.directory`가 `./public`이므로 `.git` 폴더를 정적 자산으로 공개하지 않습니다.
4. 기존 Cloudflare 배포 명령 `npx wrangler deploy`는 그대로 유지하세요. 성공 로그에 `env.DB`와 `env.ASSETS`가 나타나는지 확인하세요.

## 동작 방식

- 로그인 전에는 기존 브라우저 로컬 저장 기능을 사용합니다.
- 처음 로그인한 계정에 서버 데이터가 없다면 해당 기기의 계정별 로컬 기록 또는 게스트 기록을 최초 1회 업로드합니다. 서버에 기존 데이터가 있으면 서버 데이터가 우선합니다.
- 각 계정의 Google 고유 ID(`sub`)를 D1의 기본 키로 사용합니다. 클라이언트가 전달한 사용자 ID는 신뢰하지 않습니다.
- Google ID 토큰을 Worker에서 Google `tokeninfo`로 확인하고 audience, issuer, expiry, email verification을 검증합니다. 검증 후 HttpOnly/Secure/SameSite 쿠키를 발급하며 클라이언트 비밀번호는 필요 없습니다.
- 저장 시 버전 일치 여부를 검사합니다. 두 기기가 동시에 수정하면 자동으로 덮어쓰지 않고 충돌을 알립니다. 충돌 시 기존 기기에서 백업 후 새로고침하세요.
- 서버 저장은 입력 후 약 0.7초 뒤 실행됩니다. 오프라인/서버 오류 시 로컬 데이터가 남고 재시도합니다. 다른 기기의 변경은 해당 기기를 새로고침하거나 재로그인해야 불러옵니다. **실시간 푸시 동기화는 아닙니다.**
- 단일 계정의 데이터는 약 250KB로 제한됩니다. 사용량이 커지면 저장 구조를 개선해야 합니다.

## 확인 항목

1. PC에서 Google 로그인 → 퀘스트 추가 → `클라우드 동기화 완료` 표시 확인.
2. 휴대폰에서 같은 계정 로그인 → 동일한 퀘스트 표시 확인.
3. 휴대폰에서 완료 체크 → 동기화 완료 확인 → PC 새로고침 후 반영 확인.
4. 로그아웃 → 게스트 로컬 기록 표시 확인.

**주의:** 이 패키지는 로컬 정적 문법 검사만 마쳤습니다. Cloudflare 실제 배포, Google 로그인, D1 실제 쓰기는 사용자 계정에서 확인해야 합니다.
