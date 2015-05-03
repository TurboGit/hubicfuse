#!/bin/sh

#           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004

# Copyright (C) 2014 - Alain BENEDETTI

# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.

#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

#  0. You just DO WHAT THE FUCK YOU WANT TO.

# This program is free software. It comes without any warranty, to
#      the extent permitted by applicable law. You can redistribute it
#      and/or modify it under the terms of the Do What The Fuck You Want
#      To Public License, Version 2, as published by Sam Hocevar. See
#      http://www.wtfpl.net/ for more details.
#===========================================================

# Fonction :
# ----------
#  - This utility will get you the 'refresh_token' that is needed for your
#    programm/app/script, etc... to access your hubiC objects.
#
# Usage :
# -------
#  hubic_token [-k|--insecure] [-V|--version]
#     -k|--insecure: connects to the server even when certificate
#                    verification fails. If certificate verification fails
#                    and this option is not passed, the script will fail to
#                    protect from possible security issues.
#     -V|--version : displays the version of this script and exits.
#
#
# Tested : Ubuntu Trusty,
# ------   Synology (with coreutils and curl installed as Syno wget does NOT
#                    have HTTPS support compiled in)
#
# Depends on : - a shell (bash NOT required, dash or ash is enough)
# ----------   - sed
#              - curl (better) or wget (with HTTPS support) as a fallback.
#              No other gnu utility is necessary to run this script!
#              Optionnaly, if you have dd and base64, you will get a better
#              random seed, but that is not mandatory at all.
#
# Version : 1.0.0
# -------
#
# Date : 2014-11-28
# -----
#
# Author : Alain BENEDETTI
# ------
#
# History :
# -------
#  1.0.0
#  - Initial version
#
# Contributor :  // Add your name if you contribute and redistribute //
# -----------
#  - Sofiane, who gave me the initial raw version of the full connection script.
#  - Pascal Obry - added the URL encoding of user password

# ======================================================================================
# General notes:  the script is written to work on the Ubuntu's default shell (dash),
# --------------  thus it contains no 'bashism' and can be run easily on plaforms like
# NAS. It is also tested with Synology (with coreutils and curl installed).
#
# Why this script:  the oAuth used by hubiC (OVH) is now quite well documented but only
# ----------------  partially implemented by hubiC.
# - What is implemented: declare an "app". Here you will get the client_id and
#       client_secret necessary to authorize your app to interact. You also declare a
#       redirect_uri. This is where you should normally have to implement what is
#       missing from hubiC to get the access_token for you app! To avoid having
#       to implement anything, you can use this script instead, then the redirect_uri
#       you give can be any fake uri (as long as it is a valid uri), like for
#       example http://localhost
# - What is NOT implemented by Hubic:
#       ... well, pretty much everything else beyond declaring your app!
#       So the rest of the process is:
#       -1) deciding which permissions you grant to your 'app'
#       -2) get the refresh_token/access_token
#      For 1), you obviously need your main hubiC user/password, but once you
#      get that refresh_token, your app can connect to your hubiC account with
#      only that, plus the app id and secret... which is the purpose of oAuth
#      (authorize an app to access some of your objects without exposing your main
#      user/password).
#      So, this is a second layer above the id/secret of the app, because id/secret
#      alone is not enough to connect.
#      Let's suppose you gave id/secret AND refresh_token to someone. He can run the
#      app, and have access to what is authorized to the app. If you want to revoke
#      the authorizations of that person, you don't need to revoke the app, just run
#      this script again. You will then get a new refresh_token for yourself to connect
#      but the old refresh_token you gave to the other person won't be valid anymore.
#
# Legal concern:  I don't work at OVH... but from their perspective this script does
# --------------  not more that what you could do yourself with a browser. As you
#  don't need to run it often: just once to get the refresh_token, and once more
#  if you lose that token, there should be no harm done to OVH infrastructures!
#  It will even save some calls... for example, hubicfuse does all the process
#  everytime you connect it! So with that script, we should be able to save some
#  requests!
#  ... so, unless OVH raises any objection, this should be safe... otherwise copy
#  the requests, and do them with your browser!
#
# Security:  As this is mainly for security (and also to get better performance
# ---------  at the initialization of your app), this script does not read secrets
#  from a configuration file, nor as parameters... this is also to keep the script
#  very simple!
#  The script simply prompts for those elements.
#  Nevertheless, if you ever want to use this script in an automated way, you can:
#  - prepare a file with all the answers and redirect the input to that file.
#  - set the appropriate environment variable prior to using that script.
#  The variables are named according to their names in the hubiC requests:
#  -- client_id (The id of your app)
#  -- client_secret (The secret of your app)
#  -- redirect_uri (The redirect_uri you declared at the app creation)
#  -- scope (The authorizations you grant to the app, see hubiC's documentation).
#  -- user_login (Your main hubiC identification -the email you gave when you applied)
#     NOTE: it is called 'login' in hubiC's requests, but to avoid confusion with the
#           standard utility login, we call it here: user_login.
#  -- user_pwd (Your main hubic password)
#
# Embedding: This scripts writes only the version (when option -V is passed) and the
# ---------  final result if all went OK to standard output. All other messages go
#  to error output.
#  The exit code let you know what happened.
#  You can then easily embed this script, pipe it, or redirect the output to a file
#  for the rest of your script that needs the tokens.
# --------------------------------------------------------------------------------------



# --------------------------------------------------------------------------------------
# Internal constants                                                                   |
# --------------------------------------------------------------------------------------
URL_AUTH='https://api.hubic.com/oauth'
VERSION='1.0.0'
RANDOM_STR='TVq6zsU0A_GHIS6iYtbc7uc2c5jdpwIMczyMCsABJXbd'

# --------------------------------------------------------------------------------------
# Messages                                                                             |
# --------------------------------------------------------------------------------------
# ENGLISH
PROMPT_CLIENT_ID="client_id (the app's id): "
PROMPT_CLIENT_SECRET="client_secret (the app's secret): "
PROMPT_REDIRECT_URI="redirect_uri (declared at app's creation): "
PROMPT_USER_LOGIN='user_login (the e-mail you used to subscribe): '
PROMPT_USER_PWD="user_pwd (your hubiC's main password): "
MSG_SCOPE="For the scope -what you authorize your app to do-, enter characters as suggested
in parenthesis, or just hit return if you don't need the item authorized."
PROMPT_USAGE='Get account usage (r): '
PROMPT_GETALLLINKS='Get all published links in one call (r): '
PROMPT_CREDENTIALS='Get OpenStack credentials, eg. access to your files (r): '
PROMPT_ACTIVATE='Send activation email (w): '
PROMPT_LINKS='Add new/Get/Delete published link (wrd): '

ERR_BAD_ARG='Unknown argument: '
MSG_USAGE='Usage: '
MSG_OPTIONS=" [-k|--insecure] [-V|--version]
 -k
--insecure: connects to the server even when certificate authentication fails.
 -V
--version : displays the version of this script and exits."

MSG_VERSION=", version: "

ERR_CURL="Can't find: curl or wget. Please intall one, ex.: sudo apt-get install curl."
ERR_HTTPS="ERROR: certificate verification failed.
If you want to ignore certificate verification, use -k option."
ERR_CNX='Unexpected error trying to connect to hubiC, see error code.'
ERR_UNEXPECTED='Unexpected response from hubiC. Do your wget/curl have HTTPS support?'
ERR_SED="Can't find: sed. Please intall it."

ERR_CURL_FAILED='failed with error (see the exit code) at step'
ERR_OAUTH_NOT_FOUND="Could not find 'oauth' in the server's response."
ERR_OAUTH_HTTP="HTTP unexpected response code during oauth's request."
ERR_REASON='The server said, error: '
ERR_REASON_DESC='Error description: '
ERR_REASON_UNKNOWN="Could not parse the error message from the server's response."
ERR_CODE_NOT_FOUND="Could not find 'code' in the server's response."
ERR_CODE_HTTP="HTTP unexpected response code during code's request."
ERR_TOKEN_NOT_FOUND="Could not find 'refresh_token' in the server's response."
ERR_TOKEN_HTTP="HTTP unexpected response code during refresh_token's request."

ERR_OUT='Server full response:'

MSG_SUCCESS='Success!'
MSG_HEAD_RESULT='# Here is what your app needs to connect to hubiC:'

# --------------------------------------------------------------------------------------
# Intenationalization:  If the message files corresponding to your language,           |
# --------------------  as detected through the LANG environment variable, are         |
#                       provided, they will be used instead of fallback english        |
#                       messages defined above.                                        |
#   The language file must be in the same directory as the script. As LANG is of the   |
#   form: LANG="fr_FR.UTF-8", we will search first for: script_name_fr_FR.txt, and     |
#   if it does not exist, for script_name_fr.txt                                       |
#   The first file that exists will be sourced here. If none exist, or if LANG is not  |
#   defined in the environment variables, you get the default english messages above.  |
# --------------------------------------------------------------------------------------
if [ -n "${LANG}" ]; then
    LANG_FILE="${0}_$( printf '%.5s' "${LANG}" ).txt"
    if [ -f "${LANG_FILE}" ]; then
        . "${LANG_FILE}"
    else
        LANG_FILE="${0}_$( printf '%.2s' "${LANG}" ).txt"
        [ -f "${LANG_FILE}" ] && . "${LANG_FILE}"
    fi
fi


# --------------------------------------------------------------------------------------
# error utility                                                                        |
# $1 is the error message we want to print out (if not empty).                         |
# $2 if present, will trigger the display of the response from the server.             |
# Unless wget/curl fails, the exit code will indicate at which step we failed:         |
# -100: illegal argument                                                               |
# -101: initialization failed                                                          |
# -102: first request                                                                  |
# -103: second request                                                                 |
# -104: last request                                                                   |
# When wget/curl fails, this function is not used, and you get instead the exit code   |
# of wget/curl.                                                                        |
# Our codes begin are from 101 to 104 to be able to distinguish from wget/curl error   |
# codes that are from 1 to 89.                                                         |
# --------------------------------------------------------------------------------------
STEP=0

error()
{
    [ -n "${1}" ] && echo "${1}" >&2
    if [ -n "${2}" ] && [ -n "${out}" ]; then
        echo "${ERR_OUT}" >&2
        printf -- '%s' "${out}" >&2
    fi
    exit $(( ${STEP} + 100 ))
}

# --------------------------------------------------------------------------------------
# URL encoder                                                                          |
# $1 is a string to be passed as URL parameter                                         |
# the string is URL encoded and returned as result                                     |
# --------------------------------------------------------------------------------------

urlenc()
{
    echo "$1" | sed -e 's|%|%21|g' \
                  -e 's|!|%21|g' \
                  -e 's|#|%23|g' \
                  -e 's|\$|%24|g' \
                  -e 's| |%20|g' \
                  -e 's|&|%26|g' \
                  -e "s|'|%27|g" \
                  -e 's|(|%28|g' \
                  -e 's|)|%29|g' \
                  -e 's|*|%2A|g' \
                  -e 's|+|%2B|g' \
                  -e 's|,|%2C|g' \
                  -e 's|/|%2F|g' \
                  -e 's|:|%3A|g' \
                  -e 's|;|%3B|g' \
                  -e 's|=|%3D|g' \
                  -e 's|?|%3F|g' \
                  -e 's|@|%40|g' \
                  -e 's|\[|%5B|g' \
                  -e 's|]|%5D|g'
}

# --------------------------------------------------------------------------------------
# STEP 0: Read arguments.                                                              |
#         NOTE: to make it simple, we don't accept things like -kV because anyway it   |
#               is identical to -V                                                     |
# --------------------------------------------------------------------------------------
V=''
CURL_OPTS='-s'
for arg in "$@"; do
    case "${arg}" in
        '-k' | '--insecure' )
            CURL_OPTS='-k'
            ;;
        '-V' | '--version' )
            V='-V'
            ;;
        *)
            echo  "${ERR_BAD_ARG} '${arg}'" >&2
            error "${MSG_USAGE}$(printf -- '%s' "${0}" | sed 's|.*/||')${MSG_OPTIONS}"
    esac
done
if [ -n "${V}" ]; then
    echo "$(printf -- '%s' "${0}" | sed 's|.*/||')${MSG_VERSION}${VERSION}"
    exit 0
fi


# --------------------------------------------------------------------------------------
# STEP 1: Check the existence of programs we absolutely need (no possible fallback).   |
#         Note: we also test if there is https support on the detected wget/curl, plus |
#         that a connection to our hubiC URL returns a 301 (it is expected).           |
# --------------------------------------------------------------------------------------
STEP=1

if [ -z "$( sed --version  2>/dev/null )" ]; then
    error 1 "${ERR_SED}"
fi

if [ -z "$( curl --version  2>/dev/null )" ]; then
    if [ -z "$( wget --version  2>/dev/null )" ]; then
        error 1 "${ERR_CURL}"
    else
        CURL=wget
        CURL_DATA='--post-data'
        if [ "${CURL_OPTS}" == '-s' ]; then
            CURL_OPTS='-q'
        else
            CURL_OPTS='--no-check-certificate'
        fi
        out="$(wget -S -q "${CURL_OPTS}" --max-redirect 0 "${URL_AUTH}" -O /dev/null 2>&1)"
        ERR=$?
        [ $ERR -eq 5 ] && error "${ERR_HTTPS}"
        [ $ERR -eq 8 ] && ERR=0
    fi
else
    CURL=curl
    CURL_DATA='--data'
    out="$(curl -i -s "${CURL_OPTS}" "${URL_AUTH}")"
    ERR=$?
    [ $ERR -eq 60 ] && error "${ERR_HTTPS}"
fi
if [ $ERR -ne 0 ]; then
    echo "$ERR_CNX" >&2
    exit $ERR
else
    if [ -z "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 301/p;q' )" ]; then
        error "${ERR_UNEXPECTED}" 'y'
    fi
fi

# --------------------------------------------------------------------------------------
# curl/wget wrapper.                                                                   |
# For wget, we 'trap' the exit code 8 that only means we didn't get a 200. It is a     |
# 'normal' condition as we expect some 302, and have some documented errors with 400.  |
# --------------------------------------------------------------------------------------
ccurl()
{
    if [ "${CURL}" = 'wget' ]; then
        out="$(wget "${CURL_OPTS}" -q -O - --max-redirect 0 -S "${@}" 2>&1 )"
        ERR=$?
        [ $ERR -eq 8 ] && return 0
    else
        out="$(curl "${CURL_OPTS}" -i -s "${@}")"
        ERR=$?
    fi

    if [ $ERR -ne 0 ]; then
        echo "${CURL} ${ERR_CURL_FAILED} ${STEP}." >&2
        exit $ERR
    fi
}


# --------------------------------------------------------------------------------------
# Prompt for the variables: client_id, client_secret, etc...                           |
# NOTE: we don't prompt for account basic information access in the scope, because     |
#       apparently, even if you don't give it in the scope, it is always authorized.   |
#       So the minimal 'scope' variable will be: scope='account.r'                     |
# --------------------------------------------------------------------------------------

if [ -z "${client_id}" ]; then
    read -p "${PROMPT_CLIENT_ID}" client_id || exit $?
fi

if [ -z "${client_secret}" ]; then
    read -p "${PROMPT_CLIENT_SECRET}" client_secret || exit $?
fi

if [ -z "${redirect_uri}" ]; then
    read -p "${PROMPT_REDIRECT_URI}" redirect_uri || exit $?
fi

if [ -z "${scope}" ]; then
    printf '\n%s\n' "${MSG_SCOPE}" >&2

    scope='account.r'

    read -p "${PROMPT_USAGE}" usage || exit $?
    [ "$usage" = 'r' ] && scope="${scope},usage.r"

    read -p "${PROMPT_GETALLLINKS}" getAllLinks || exit $?
    [ "$getAllLinks" = 'r' ] && scope="${scope},getAllLinks.r"

    read -p "${PROMPT_CREDENTIALS}" credentials || exit $?
    [ "$credentials" = 'r' ] && scope="${scope},credentials.r"

    read -p "${PROMPT_ACTIVATE}" activate || exit $?
    [ "$activate" = 'w' ] && scope="${scope},activate.w"

    read -p "${PROMPT_LINKS}" links || exit $?
    l="$( printf -- '%s' "${links}" | sed 's/[^\(w\|r\|d\)]//g' )"
    [ -n "$l" ] && [ "${l}" = "${links}" ] && scope="${scope},links.${l}"
    printf '\n' >&2
fi

if [ -z "${user_login}" ]; then
    read -p "${PROMPT_USER_LOGIN}" user_login || exit $?
fi





# --------------------------------------------------------------------------------------
# Each step is based on the same principle:                                            |
# - Prepare and send the request.                                                      |
# - extract a string from the response.                                                |
# - error handling:                                                                    |
#       = An error can happen during the request, in which case we exit with the       |
#         return code of wget/curl.                                                    |
#       = An error can happen when trying to extract the string, if we can't find the  |
#         string we search. The error message and entire server response will be       |
#         displayed in this case.                                                      |
#       = There are some "documented" errors, generally indicated by a different HTTP  |
#         status code. Should such error happen, we will then try to extract and       |
#         display the documented message. Again if this documented message cannot be   |
#         extracted, or we have another HTTP status, the whole response is dumped.     |
#                                                                                      |
# STEP2: getting oauth                                                                 |
#        The expected response is a html page with HTTP status 200.                    |
#        From this page we extract 'oauth' which is the value here:                    |
#           ... name="oauth" value="168341"><input type="hidden" name="action" ...     |
#        Error extraction is on HTTP status 302 in the location response header.       |
# --------------------------------------------------------------------------------------
STEP=2

  # FALLBACK: if either dd or base64 are not found or fail, we keep the initial
  #           RANDOM_STR, thus it is not random anymore, but at least the script works!
rnd="$(dd if=/dev/urandom bs=1 count=33 2>/dev/null | base64 -w 0 2>/dev/null)" && RANDOM_STR="${rnd}"

URL="${URL_AUTH}/auth/?client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}&response_type=code&state=${RANDOM_STR}"

ccurl "${URL}"

if [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 200/p;q' )" ]; then
    oauth="$(echo "${out}" | sed -n '/oauth/s/.*name=\"oauth\" value=\"\(.*\)\"><input type=\"hidden\" name=\"action\".*/\1/p')"
    if  [ -z "$oauth" ]; then
        error "${ERR_OAUTH_NOT_FOUND}" 'y'
    fi
else
    echo "${ERR_OAUTH_HTTP}" >&2
    if [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 302/p;q' )" ]; then
        ERR="$( printf '%s' "${out}" | sed -n 's/\&.*//;/error=/s/.*error=//p' )"
        if [ -n "${ERR}" ]; then
            printf "${ERR_REASON}%s\n" "${ERR}" >&2
            ERR="$( printf '%s' "${out}" | sed -n 's/.*error_description=//;s/\&.*//p' )"
            if [ -n "${ERR}" ]; then
                printf "${ERR_REASON_DESC}%s\n" "${ERR}" >&2
            fi
            error ''
        else
            error "${ERR_REASON_UNKNOWN}" 'y'
        fi
    fi
    error '' 'y'
fi


# --------------------------------------------------------------------------------------
# STEP3: setting app permissions and getting 'code'                                    |
#        The expected response is a redirect (302).                                    |
#        We extract the 'code' from the Location header of the redirect:               |
# Location: http://localhost/?code=14163171312491G7k3O0O2VGbRyk8t83&scope=usage.r ...  |
#                                                                                      |
# Error extraction, if instead we get a 200, it is probably a bad login/user_pwd, so   |
#        we extract the error given by the server (in the HTML page).                  |
#                                                                                      |
# NOTE: the user_pwd is read here for security reason, because we don't need it before |
#       this step. It is done inside a subshell to reduce its presence in memory.      |
#       Also note that dash does not have the -s option for read, hence we use the     |
#       stty command (hopefully it exists and works!..). We also disable tracing in    |
#       the subshell, to avoid having the password displayed if the script was runned  |
#       with traces on.                                                                |
# --------------------------------------------------------------------------------------
STEP=3

out="$(
    set +x
    if [ -z "${user_pwd}" ]; then
        printf -- '%s' "${PROMPT_USER_PWD}" >&2
        stty -echo 2>/dev/null
        read user_pwd || exit $?
        stty echo 2>/dev/null
    fi
    printf '\n' >&2
    POST="$( printf '%s' "${scope}" | sed 's|,|\&|g;s|\.|=|g' )&oauth=${oauth}&action=accepted&login=$(urlenc "${user_login}")&user_pwd=$(urlenc "${user_pwd}")"

    ccurl "${URL_AUTH}/auth/" "${CURL_DATA}" "${POST}"

    printf -- '%s' "${out}"
)" || exit $?

if [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 302/p;q' )" ]; then
    code="$(echo "${out}" | sed -n "s/.*?code=\(.*\)\&scope.*/\1/p")"
    if  [ -z "$code" ]; then
        error "${ERR_CODE_NOT_FOUND}" 'y'
    fi
else
    echo "${ERR_CODE_HTTP}" >&2
    if [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 200/p;q' )" ]; then
        ERR="$( printf '%s' "${out}" | sed -n '/class="text-error"/!d;N;s/.*\n//;s/^[ \t]*//;p' )"
        if [ -n "${ERR}" ]; then
            printf "${ERR_REASON}%s\n" "${ERR}" >&2
            error ''
        else
            error "${ERR_REASON_UNKNOWN}" 'y'
        fi
    fi
    error '' 'y'
fi


# --------------------------------------------------------------------------------------
# STEP4: getting the refresh_token                                                     |
#        The expected response is a JSON object (HTTP/1.1 200).                        |
#        Documented errors are with 400 and 401 return codes. We don't try to extract  |
#        error strings with wget, because wget simply exits with an error when not     |
#        receiving a 200 (the exception is 302 with can still be caugh). So when using |
#        wget, either this works (200) or we display the whole response.               |
# --------------------------------------------------------------------------------------
STEP=4

POST="client_id=${client_id}&client_secret=${client_secret}&code=${code}&grant_type=authorization_code"

if [ "${CURL}" = 'wget' ]; then
    POST="${POST}&redirect_uri=${redirect_uri}"
    CURL_ENCODE='-q'
    REDIR='-q'
else
    CURL_ENCODE='--data-urlencode'
    REDIR="redirect_uri=${redirect_uri}"
fi
ccurl "${URL_AUTH}/token/" \
      "${CURL_DATA}" "${POST}" \
      "${CURL_ENCODE}" "${REDIR}"

if [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 200/p;q' )" ]; then
    refresh_token="$( printf '%s' "${out}" | sed -n 's/{\"refresh_token\":\"//;s/\",\"expires_in\".*//p' )"
    if  [ -z "$refresh_token" ]; then
        error "${ERR_TOKEN_NOT_FOUND}" 'y'
    fi
else
    echo "${ERR_TOKEN_HTTP}" >&2
    if [ "${CURL}" = 'curl' ] && [ -n "$( printf '%s' "${out}" | sed -n '/1/h;/HTTP\/1\.1 40\(0\|1\)/p;q' )" ]; then
        ERR="$( printf '%s' "${out}" | sed -n 's/"}//;/"error"/s/.*"error":"//p' )"
        if [ -n "${ERR}" ]; then
            printf "${ERR_REASON}%s\n" "${ERR}" >&2
            ERR="$( printf '%s' "${out}" | sed -n 's/","error".*//;/error_description/s/{"error_description":"//p' )"
            if [ -n "${ERR}" ]; then
                printf "${ERR_REASON_DESC}%s\n" "${ERR}" >&2
            fi
            error ''
        else
            error "${ERR_REASON_UNKNOWN}" 'y'
        fi
    fi
    error '' 'y'
fi


# --------------------------------------------------------------------------------------
# THE END: we display the final result if all was successful                           |
# --------------------------------------------------------------------------------------

echo  >&2
echo "${MSG_SUCCESS}" >&2
echo  >&2
echo  >&2
echo "${MSG_HEAD_RESULT}"
echo "client_id=${client_id}"
echo "client_secret=${client_secret}"
echo "refresh_token=${refresh_token}"
