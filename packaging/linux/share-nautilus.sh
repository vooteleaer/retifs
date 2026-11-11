#!/bin/sh
# "Share with retifs" in Nautilus (Files): the selected files, or one folder,
# inside a retifs folder (~/retifs/<library>) become a share of their own,
# kept up to date (ADR-0021). retifsd puts this script in
# ~/.local/share/nautilus/scripts/ when Nautilus is there.
IFS='
'
# shellcheck disable=SC2086 # one path per line, as Nautilus gives them
out=$(retifs share path $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS 2>&1)
status=$?
title="Shared with retifs"
[ $status -eq 0 ] || title="Not shared"
if command -v zenity >/dev/null 2>&1; then
    if [ $status -eq 0 ]; then zenity --info --title "$title" --text "$out" --no-markup
    else zenity --error --title "$title" --text "$out" --no-markup; fi
elif command -v notify-send >/dev/null 2>&1; then
    notify-send "$title" "$out"
fi
