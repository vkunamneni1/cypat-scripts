#!/usr/bin/env bash

BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}This script was brought to you by atomtables and swaroop for CPC under MCA/EAMS...${NC}"
read -t 5

echo -e "Listing all media files from the *entire* system (this may take a moment):\n"

echo -e "${CYAN}Image files:"
find / -type f -regextype egrep -regex '.*\.(jpg|jpeg|png|tiff|bmp|gif)$' 2>/dev/null
echo -e "${MAGENTA}Audio files:"
find / -type f -regextype egrep -regex '.*\.(mp3|wav|ogg|flac)$' 2>/dev/null
echo -e "${BLUE}Video files:"
find / -type f -regextype egrep -regex '.*\.(mp4|mov|mkv)' 2>/dev/null
echo -e "${YELLOW}Document files:"
find / -type f -regextype egrep -regex '.*\.(txt|docx|doc|xlsx|csv|pptx)' 2>/dev/null
echo -e "${GREEN}Adobe files:"
find / -type f -regextype egrep -regex '.*\.(psd|pdf)' 2>/dev/null
echo -e "${RED}Extractables files:"
find / -type f -regextype egrep -regex '.*\.(zip|rar|7z|tar|tar.gz|tar.xz)' 2>/dev/null
echo -e "${WHITE}Executable files:"
find / -type f -regextype egrep -regex '.*\.(sh|bash|deb|rpm|appimage)' 2>/dev/null

echo -e "\nSearch complete."
