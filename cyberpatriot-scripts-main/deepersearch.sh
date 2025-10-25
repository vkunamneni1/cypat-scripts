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

echo -e "Listing all media files:\n"

echo -e "${CYAN}Image files:"
find /home -type f -regextype egrep -regex '.*\.(jpg|jpeg|png|tiff|bmp|gif)$'
echo -e "${MAGENTA}Audio files:"
find /home -type f -regextype egrep -regex '.*\.(mp3|wav|ogg|flac)$'
echo -e "${BLUE}Video files:"
find /home -type f -regextype egrep -regex '.*\.(mp4|mov|mkv)'
echo -e "${YELLOW}Document files:"
find /home -type f -regextype egrep -regex '.*\.(txt|docx|doc|xlsx|csv|pptx)'
echo -e "${GREEN}Adobe files:"
find /home -type f -regextype egrep -regex '.*\.(psd|pdf)'
echo -e "${RED}Extractables files:"
find /home -type f -regextype egrep -regex '.*\.(zip|rar|7z|tar|tar.gz|tar.xz)'
echo -e "${WHITE}Executable files:"
find /home -type f -regextype egrep -regex '.*\.(sh|bash|deb|rpm|appimage)'


