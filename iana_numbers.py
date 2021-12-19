
#https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
icmp_type_code = {
                    (8,0) : "Echo : Request", 
                    (0,0) : "Echo : Reply", 
                    (3,0) : "Net : Unreachable", 
                    (3,1) : "Host : Unreachable", 
                    (3,2) : "Protocol : Unreachable",
                    (3,3) : "Port : Unreachable" ,
                    (3,6) : "Destination_Network : Unknown", 
                    (3,7) : "Destination_Host : Unknown", 
                    (3,9) : "Communication_with_Destination_Network : Administratively_Prohibited", 
                    (3,10) : "Communication_with_Destination_Host : Administratively_Prohibited", 
                    (3,11) : "Destination_Network : Unreachable_for_Type_of_Service", 
                    (3,12) : "Destination_Host : Unreachable_for_Type_of_Service", 
                    (3,13) : "Communication : Administratively_Prohibited"
                    }

#https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
icmp6_type_code = {
                    (1,0)   : "Destination_Unreachable : no_route_to_destination",
                    (1,1)   : "Destination_Unreachable : communication_with_destination_administratively_prohibited",
                    (1,2)   : "Destination_Unreachable : beyond_scope_of_source_address",
                    (1,3)   : "Destination_Unreachable : address_unreachable",
                    (1,4)   : "Destination_Unreachable : port_unreachable",
                    (1,5)   : "Destination_Unreachable : source_address_failed_ingress/egress_policy",
                    (1,6)   : "Destination_Unreachable : reject_route_to_destination",
                    (1,7)   : "Destination_Unreachable : Error_in_Source_Routing_Header",
                    (1,8)   : "Destination_Unreachable : Headers_too_long",
                    (2,0)   : "Packet : Too Big",
                    (3,0)   : "Time_Exceeded : Hop_limit_exceeded_in_transit",
                    (3,1)   : "Time_Exceeded : Fragment_reassembly_time_exceeded",
                    (4,0)   : "Parameter_Problem : Erroneous_header_field_encountered",
                    (4,1)   : "Parameter_Problem : Unrecognized_Next_Header_type_encountered",
                    (4,2)   : "Parameter_Problem : Unrecognized_IPv6_option_encountered",
                    (4,3)   : "Parameter_Problem : IPv6_First_Fragment_has_incomplete_IPv6_Header_Chain",
                    (4,4)   : "Parameter_Problem : SR_Upper-layer_Header_Error",
                    (4,5)   : "Parameter_Problem : Unrecognized_Next_Header_type_encountered_by_intermediate_node",
                    (4,6)   : "Parameter_Problem : Extension_header_too_big",
                    (4,7)   : "Parameter_Problem : Extension_header_chain_too_long",
                    (4,8)   : "Parameter_Problem : Too_many_extension_headers",
                    (4,9)   : "Parameter_Problem : Too_many_options_in_extension_header",
                    (4,10)   : "Parameter_Problem : Option_too_big",
                    (128,0) : "Echo : Request", 
                    (129,0) : "Echo : Reply",
                    (130,0) : "Multicast_Listener : Query", 
                    (131,0) : "Multicast_Listener : Report", 
                    (132,0) : "Multicast_Listener : Done", 
                    (133,0) : "Router : Solicitation", 
                    (134,0) : "Router : Advertisement", 
                    (135,0) : "Neighbor : Solicitation", 
                    (136,0) : "Neighbor : Advertisiement", 
                    (137,0) : "Redirect : Message", 
                    (143,0) : "Multicast_Listener : Report_Message_v2" 
                    }

#https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
protocols = {
                    0: "HbH", 
                    1: "ICMP", 
                    2: "IGMP", 
                    6: "TCP", 
                    17: "UDP",
                    43: "RoutingH",
                    44: "FragmentH",
                    58: "ICMPv6",
                    60: "DestOptH"
                    }
