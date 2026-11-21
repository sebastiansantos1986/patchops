#!/bin/bash
# PatchOps / Jamf Pro extension attribute: installed Java runtimes.
#
# Jamf Pro: Settings > Computer management > Extension attributes > New
#   Display name: Java Versions      Data type: String      Input type: Script
# Paste this script. Inventory updates will then report, for example:
#   <result>17.0.12 (Eclipse Temurin), 21.0.4 (Oracle)</result>   or   <result>None</result>
# PatchOps reads it from Jamf and you can query it in Explore:
#   r/ ( e/ ExtensionAttribute f/ Name = "Java Versions" f/ Value contains 17. )
#
# Read-only: it only lists what is installed.

found=()

add_jvm() { # $1 = path to a JDK/JRE "Contents" directory or home
  local plist="$1/Info.plist"
  local version="" vendor=""
  if [[ -f "$plist" ]]; then
    version=$(/usr/libexec/PlistBuddy -c "Print :JavaVM:JVMVersion" "$plist" 2>/dev/null)
    [[ -z "$version" ]] && version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$plist" 2>/dev/null)
    vendor=$(/usr/libexec/PlistBuddy -c "Print :JavaVM:JVMVendor" "$plist" 2>/dev/null)
  fi
  if [[ -z "$version" && -f "$1/Home/release" ]]; then
    version=$(awk -F'"' '/^JAVA_VERSION=/{print $2}' "$1/Home/release")
    vendor=$(awk -F'"' '/^IMPLEMENTOR=/{print $2}' "$1/Home/release")
  fi
  if [[ -z "$version" && -f "$1/release" ]]; then
    version=$(awk -F'"' '/^JAVA_VERSION=/{print $2}' "$1/release")
    vendor=$(awk -F'"' '/^IMPLEMENTOR=/{print $2}' "$1/release")
  fi
  [[ -n "$version" ]] && found+=("${version}${vendor:+ ($vendor)}")
}

# System-wide JDKs (standard .pkg/.dmg installs)
for jvm in /Library/Java/JavaVirtualMachines/*/Contents; do [[ -d "$jvm" ]] && add_jvm "$jvm"; done
# Per-user JDKs (e.g. installed by IDEs or SDKMAN)
for jvm in /Users/*/Library/Java/JavaVirtualMachines/*/Contents; do [[ -d "$jvm" ]] && add_jvm "$jvm"; done
for jvm in /Users/*/.sdkman/candidates/java/*; do [[ -d "$jvm" && "$(basename "$jvm")" != "current" ]] && add_jvm "$jvm"; done
# Homebrew OpenJDK (Apple silicon and Intel prefixes)
for jvm in /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents; do [[ -d "$jvm" ]] && add_jvm "$jvm"; done
# Legacy Java 8 browser plug-in JRE
plugin="/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents"
[[ -d "$plugin" ]] && add_jvm "$plugin"

if [[ ${#found[@]} -eq 0 ]]; then
  echo "<result>None</result>"
else
  printf '%s\n' "${found[@]}" | sort -u | paste -sd ',' - | sed 's/,/, /g' | awk '{print "<result>"$0"</result>"}'
fi
