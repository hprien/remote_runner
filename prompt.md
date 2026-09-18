dont commit code on your own
read and maintain README.md
focus is a minimalistic and clean go codebase
stick to go standard lib where possible
expose a webserver authenticate yourself with a self signed certificate (docu to readme) authenticate the user with a self signed certificate
validate all user input
throw errors instead of silently ignoring them
enforce tls1.3 for every connection certificates are not being checked against a ca, certificates are pinned
# API:
## request:
{
  "script_name": str,
  "script_checksum": str,
  "stream_script_stdout_stderr: bool,
  "script_response_webhook_url": str,
  "webhook_delay_seconds": int,
  "script_timeout_seconds": int
}
in folder scripts a folder with script_name contains a executable file script_name script_checksum must match a secure checksum of the script to ensure the executable file was not changed.
only script_response_webhook_url and webhook_delay_seconds are optional
when stream_script_stdout_stderr is true, stream the stdout and stderr to the client
webhook_delay_seconds defines a delay for fetching webhook after the script finished
when the script didn't finish after script_timeout_seconds terminate it and send webhook it wanted by user
let only run a configurable amount of scripts simultaniously to prevent dos
let script_timeout_seconds nnd webhook_delay_seconds have a seperate configurable max value to prevent dos
add advice to readme on how to create a user that runs this script automaticaly at system start
make it possible to configure both server and client certificate for webhook calls. remote_runner presents the client certificate and chacks the pinned server certificate
protect script name from containin gpath traversal
## response 200:
{
  "type": "accepted" | "denied",
  "script_name": "hello",
  "message": "Script execution started" | "too many concurrent scripts"
}
{
  "type": "stdout" | "stderr",
  "txt": str
}
## webhook response after script finished and webhook_delay_seconds
{
    "script_name": str,
    "stdout": str,
    "stderr": str,
    "return_code": int
}
## response bad request:
jsut return "bad request" no details

# logging
log to journalctl give details on how to view logs in readme
log security relevant events for a siem
log every request (transaction_id, source ip, timestamp, request message)
transaction_id is used to trace log messages belonging to one request (uuid)
log every response (transaction_id, timestamp, response message)
log script execution started, aborted etc.
log when and why webhook call failed (no retries)