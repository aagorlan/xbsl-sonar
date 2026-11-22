#!/usr/bin/env bash
set -euo pipefail
: "${GITFLIC_REPO:?Задайте путь проекта GitFlic}" "${GITFLIC_LOGIN:?Задайте логин GitFlic}" "${GITFLIC_TOKEN:?Задайте токен GitFlic}"
[[ "$GITFLIC_REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/askpass" <<'ASK'
#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "$GITFLIC_LOGIN" ;;
  *Password*) printf '%s\n' "$GITFLIC_TOKEN" ;;
  *) exit 1 ;;
esac
ASK
chmod 700 "$tmp/askpass"
export GIT_ASKPASS="$tmp/askpass" GIT_TERMINAL_PROMPT=0 LC_ALL=C
remote="https://gitflic.ru/project/$GITFLIC_REPO.git"
api="https://api.gitflic.ru/project/$GITFLIC_REPO/release"
api_call() { curl -fsS -H "Authorization: token $GITFLIC_TOKEN" "$@"; }
git push "$remote" refs/heads/main:refs/heads/main 'refs/tags/*:refs/tags/*'
git show-ref --heads --tags | awk '$2=="refs/heads/main" || $2 ~ /^refs\/tags\// {print $1,$2}' | sort > "$tmp/source"
git ls-remote --refs "$remote" refs/heads/main 'refs/tags/*' | awk '{print $1,$2}' | sort > "$tmp/mirror"
diff -u "$tmp/source" "$tmp/mirror"

# У анализатора выпуски без вложений. При появлении первого файла требуем его переноса.
gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" | jq -sc '
  add | map(select(.draft|not)) |
  if any(.[]; (.assets|length)>0) then error("В выпуске есть вложения") else . end |
  map({tagName:.tag_name,title:(.name//""),description:(.body//""),preRelease:.prerelease}) |
  sort_by(.tagName)' > "$tmp/expected"
read_releases() {
  local page=0
  while :; do
    status=$(curl -sS -w '%{http_code}' -o "$tmp/page" -H "Authorization: token $GITFLIC_TOKEN" "$api?page=$page&size=100")
    if [[ "$status" == 404 && "$page" == 0 ]]; then
      printf '[]\n'
      break
    fi
    [[ "$status" == 200 ]] || { echo "Список выпусков: HTTP $status" >&2; return 1; }
    jq -ce 'if type=="array" then . elif (.result|type)=="array" then .result elif (.content|type)=="array" then .content elif (._embedded|type)=="object" then [._embedded[] | arrays | .[]] else error("Неизвестный формат списка выпусков") end' "$tmp/page" > "$tmp/items"
    cat "$tmp/items"
    [[ $(jq length "$tmp/items") -lt 100 ]] && break
    page=$((page+1))
  done
}
normalize() { jq -sc 'add | map({tagName,title,description:(.description//""),preRelease:(.preRelease//false)}) | sort_by(.tagName)'; }
read_releases | normalize > "$tmp/current"
jq -c --slurpfile old "$tmp/current" '.[] | select(.tagName as $tag | all($old[0][]; .tagName!=$tag)) | . + {attachProjectArchive:false}' "$tmp/expected" > "$tmp/missing"
while IFS= read -r release; do
  api_call -X POST -H 'Content-Type: application/json' --data "$release" "$api" > /dev/null
done < "$tmp/missing"
read_releases | normalize > "$tmp/current"
diff -u "$tmp/expected" "$tmp/current"
