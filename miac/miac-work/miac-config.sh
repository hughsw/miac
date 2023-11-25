#!/bin/bash

height=10
width=60

outfile=$(mktemp)
dialog \
    --title "Miac Server Configuration" --cr-wrap --trim --inputbox "\nWelcome!  Just a few questions and your mail-in-a-container server will be configured.\n\nEnter the domain name you are configuring." $((height + 2)) $width \
    2> $outfile
domain=$(< $outfile)
rm $outfile

outfile=$(mktemp)
dialog \
    --title "Email Server Hostname" --cr-wrap --trim --inputbox "\nEnter a hostname for the server.  This will the be name of the website that users go to for their webmail." $height $width "shed.$domain" \
    --title "Timezone" --cr-wrap --trim --inputbox "\nEnter a timezone for the server.  We suggest using Etc/UTC." $height $width "Etc/UTC" \
    --title "Admin Email" --cr-wrap --trim --inputbox "\nEnter an email address for the admin account.  This will be the administrative user who manages the webmail server." $height $width "admin@$domain" \
    --title "Admin Password" --cr-wrap --trim --insecure --passwordbox "\nEnter admin password" $height $width \
    --title "Admin Password verify" --cr-wrap --trim --insecure --passwordbox "\nRe-enter admin password" $height $width \
    2> $outfile
config=$(< $outfile)
rm $outfile

echo
echo $domain
for part in $config ; do
    echo $part
done
