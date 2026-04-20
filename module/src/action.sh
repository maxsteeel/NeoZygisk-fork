printf "Status of NeoZygisk\n\n"

cat @WORK_DIRECTORY@/status.prop

if [[ -z "$MMRL" ]] && ([[ -n "$KSU" ]] || [[ -n "$APATCH" ]]); then
	# Avoid instant exit on KernelSU or APatch
	sleep 5
fi
