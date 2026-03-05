on run argv
    set volName to item 1 of argv
    set appName to item 2 of argv

    tell application "Finder"
        tell disk volName
            open
            set current view of container window to icon view
            set toolbar visible of container window to false
            set statusbar visible of container window to false
            set the bounds of container window to {100, 100, 700, 500}
            set viewOptions to the icon view options of container window
            set arrangement of viewOptions to not arranged
            set icon size of viewOptions to 80
            set background picture of viewOptions to file ".background:background.png"
            set position of item appName of container window to {150, 200}
            set position of item "Applications" of container window to {450, 200}
            close
            open
            update without registering applications
            delay 2
            close
        end tell
    end tell
end run
