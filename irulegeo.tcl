when CLIENT_ACCEPTED {
    set ip_client_addr [getfield [IP::client_addr] "%" 1]
    if { [class match $ip_client_addr equals "IP_WHITE_LIST"] } then {
        # Allowed by IP_WHITE_LIST
        set blocked_ip 0
    } elseif  { [class match [whereis $ip_client_addr country] equals "GEO_WHITE_LIST"] } then {
         # Allowed by GEO_WHITE_LIST
        set blocked_ip 0
    } else {
        set blocked_ip 1
    }
}
when HTTP_REQUEST {
    if { $blocked_ip == 1 } then {
        # Sending Access denied 
        HTTP::respond 403 content "Access denied" "Content-Type" "text/text" "Connection" "close"
    }
}
