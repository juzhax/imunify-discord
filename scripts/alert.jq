# Called with --arg mode normalize|payload|keys, --arg host, --arg simulated.
def scalar: if type=="string" or type=="number" then tostring else "" end;
def first($names): . as $d | [$names[] | $d[.] | scalar | select(length>0)][0] // "";
def clean: scalar | gsub("https://(?:discord\\.com|discordapp\\.com)/api/webhooks/[^\\s]+"; "[redacted webhook]"; "i")
  | gsub("[\\x00-\\x1f\\x7f]"; " ") | gsub("`"; "'") | gsub("@"; "@\u200b") | .[0:220];
def owner: if startswith("/home/") then split("/")[2] // "" else "" end;
def events: ["CUSTOM_SCAN_MALWARE_FOUND","USER_SCAN_MALWARE_FOUND"];
def record($user):
  (if type=="string" then {path:.} elif type=="object" then . else {} end) as $r |
  ($r|first(["path","file","filename","file_path"])) as $path |
  ($r|first(["type"])) as $kind |
  {path:$path, user:($r|first(["username","user","owner"])),
   signature:($r|first(["signature","malware_name","threat"])),
   hash:($r|first(["sha256","hash","checksum"])), id:($r|first(["detection_id","id"]))} |
  if .user=="" then .user=($path|owner) else . end |
  if .user=="" then .user=$user else . end |
  if .signature=="" and ((events + ["user","background","on-demand","custom"]|index($kind))==null)
    then .signature=$kind else . end |
  select(.path!="" or .signature!="" or .hash!="" or .id!="");
def normalize:
  (if type=="object" then . else {} end) |
  (reduce range(0;4) as $i ({merged:.,current:.};
    (.current | [.data,.params,.payload] | map(select(type=="object")) | .[0] // {}) as $child |
    .merged += $child | .current=$child) | .merged) as $d |
  ([$d.event_id,$d.event,$d.event_type,($d.event|if type=="object" then first(["event_id","name","type"]) else "" end),
     ($d.type|select(. as $t|events|index($t)))] | map(scalar|select(length>0))) as $types |
  ([$types[]|select(. as $t|events|index($t))][0] // $types[0] // "UNKNOWN_MALWARE_EVENT") as $event |
  ($d|first(["path","scan_path"])) as $path |
  (($d|first(["username","user","owner"])) as $u |
    if $u!="" then $u elif ($d.user|type)=="object" then ($d.user|first(["username","name","login"])) else ($path|owner) end) as $user |
  ([$d.malicious_files,$d.detections,$d.infected_files,$d.files] | map(select((type=="array" or type=="object") and length>0)) | .[0] // []) as $files |
  (if ($files|type)=="array" then [$files[]|record($user)]
   elif ($files|has("path") or has("file") or has("filename") or has("file_path")) then [$files|record($user)]
   else [$files|to_entries[]|
     if (.key|startswith("/")) then ({path:.key} + (if (.value|type)=="object" then .value else {signature:(.value|scalar)} end)) | record($user)
     else .key as $u | .value | (if type=="array" then .[] else . end) | record($u) end] end) as $records |
  (if ($records|length)==0 and ($d|has("signature") or has("malware_name") or has("threat") or has("file_path"))
    then [$d|record($user)] else $records end) as $all |
  {event_type:$event,user:$user,path:$path,scan_id:($d|first(["scan_id"])),occurrence:($d|first(["started","completed"])),
   total:($d|first(["total_malicious","malicious_total","malware_count"])),
   count:($all|length), incomplete:(($all|length)>200), records:$all[0:200]};
if $mode=="normalize" then normalize
elif $mode=="keys" then
  if .incomplete then empty else
    (if .scan_id!="" then .scan_id else .occurrence end) as $scope |
    if (.records|length)==0 and $scope!="" then [$scope,.user,.path]|tojson
    else .records[] | select(.path!="" or .hash!="" or .id!="") |
      [$scope,.path,.user,.signature,.hash,.id]|tojson end
  end
elif $mode=="payload" then
  . as $e |
  ([.records[].user,.user]|map(select(length>0))|unique|join(", ")|clean) as $users |
  ([if $simulated=="true" then "SIMULATED TEST — no scan or detection history changed." else "**ImunifyAV malware detected**" end,
    "Server: " + ($host|clean), "Event: " + (.event_type|clean),
    "Affected user(s): " + (if $users=="" then "not supplied" else $users end),
    "Scan path: " + (if .path=="" then "not supplied" else (.path|clean) end),
    "Detected malware: " + (if .total!="" then (.total|clean) elif .count>0 then (.count|tostring) else "not supplied" end)] +
    (if (.records|length)==0 then ["File/signature details were not supplied by ImunifyAV."]
     else [.records[0:6][] | "- " + (if .path=="" then "path not supplied" else (.path|clean) end) +
       (if .signature!="" then " | signature: " + (.signature|clean) else "" end) +
       (if .hash!="" then " | hash: " + (.hash|clean) else "" end)] end) | join("\n") | .[0:1800]) as $body |
  {username:($host|clean|.[0:80]),content:($body+"\nReview findings in DirectAdmin → ImunifyAV. No cleanup, quarantine or deletion was requested."),allowed_mentions:{parse:[]}}
else error("unknown mode") end
