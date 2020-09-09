#!/usr/bin/python3.6
"""print_analyze module contains function that print output of device_analyzer module.


    Copyright (C) 2020 CESNET

    LICENSE TERMS

        Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
            1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  
            2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

            3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

        ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above. 

        This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
"""
# Standard Library Imports
import time
import socket

# Local Application Imports
from statistics import plot_statistics
from create_script import check_str


def print_device_from_json(json_output, args):
    """Print device from output JSON document to command line.

    Parameters
    -----------
    json_output : JSON
        Ouput JSON document.
    args : argparse
        Setted arguments of the DeviceAnalyzer script.    
    """
    if (
        not json_output["LocalDependencies"]
        and not json_output["GlobalDependencies"]
        and not json_output["Labels"]
    ):
        return
    print("######################################################################")
    print("Device ID: ", json_output["DeviceID"])
    # =================================================================================
    print("  IP: ", end="")
    tmp = 0
    for i in json_output["IP"]:
        if tmp == 0:
            print(i, end="")
            tmp = i
        else:
            print(" <", i, ">", end="")
    print("")
    print("  MAC: ", end="")
    if json_output["MAC"] == "" and json_output["RouterMAC"] == "":
        print("---")
    elif json_output["RouterMAC"] == "":
        print(json_output["MAC"], end="")
        if json_output["Vendor"] != "":
            print(", ", json_output["Vendor"], ", ", json_output["Country"])
    else:
        print(
            " of router behind this device or this device itself is this router: ",
            json_output["RouterMAC"],
            end="",
        )
        if json_output["Vendor"] != "":
            print(", ", json_output["Vendor"], ", ", json_output["Country"])
    # =================================================================================
    print("  Labels:")
    if not json_output["Labels"]:
        print("    ---")
    for i in json_output["Labels"]:
        if args.DNS == True and i["Label"] == "WEB Server":
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain)
            except:
                print("    [", i["Label"], "] - ", i["Description"])
        else:
            print("    [", i["Label"], "] - ", i["Description"])
    # =================================================================================
    print("  DHCP:")
    if not json_output["DHCP"]:
        print("    ---")
    for i in json_output["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"])
    # =================================================================================
    print("  Local Dependencies:")
    if not json_output["LocalDependencies"]:
        print("    ---")
    if args.LocalNumber != -1:
        tmp = 0
        for i in json_output["LocalDependencies"]:
            if tmp < args.LocalNumber:
                if i["Verb"] == "provides":
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                    )
                else:
                    print(
                        "    <- ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                    )
                tmp = tmp + 1
            else:
                break
    else:
        for i in json_output["LocalDependencies"]:
            if i["Verb"] == "provides":
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
            else:
                print(
                    "    <- ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
    # =================================================================================
    if not json_output["LocalStatistic"]:
        print("")
    else:
        ip_address_statistics = {}
        for i in json_output["LocalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        plot_statistics(ip_address_statistics.items())
    # =================================================================================
    print("  Global Dependencies:")
    if not json_output["GlobalDependencies"]:
        print("    ---")
    if args.GlobalNumber == -1:
        for i in json_output["GlobalDependencies"]:
            if args.DNS == True:
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")]  Domain: ",
                            domain[0],
                            "  - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")]  Domain: ",
                            domain[0],
                            "  - number of packets: ",
                            i["Packets"],
                        )
                except:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
            else:
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
    else:
        tmp = 0
        for i in json_output["GlobalDependencies"]:
            if tmp < args.GlobalNumber:
                if args.DNS == True:
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                            )
                    except:
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                            )
                else:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                tmp = tmp + 1
            else:
                break
    # =================================================================================
    if not json_output["GlobalStatistic"]:
        print("")
    else:
        ip_address_statistics = {}
        for i in json_output["GlobalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        plot_statistics(ip_address_statistics.items())


def print_device_to_file_from_json(json_output, args, sample):
    """Print device from output JSON document to file.

    Parameters
    -----------
    json_output : JSON
        Ouput JSON document.
    args : argparse
        Setted arguments of the DeviceAnalyzer script.    
    sample : opened file
        Opened output file.
    """
    if not json_output["LocalDependencies"] and not json_output["GlobalDependencies"]:
        return
    print(
        "######################################################################",
        file=sample,
    )
    print("Device ID: ", json_output["DeviceID"], file=sample)
    # =================================================================================
    print("  IP: ", end="", file=sample)
    tmp = 0
    for i in json_output["IP"]:
        if tmp == 0:
            print(i, end="", file=sample)
            tmp = i
        else:
            print(" <", i, ">", end="", file=sample)
    print("", file=sample)
    print("  MAC: ", end="", file=sample)
    if json_output["MAC"] == "" and json_output["RouterMAC"] == "":
        print("---", file=sample)
    elif json_output["RouterMAC"] == "":
        print(json_output["MAC"], end="", file=sample)
        if json_output["Vendor"] != "":
            print(
                ", ", json_output["Vendor"], ", ", json_output["Country"], file=sample
            )
    else:
        print(
            " of router behind this device or this device itself is this router: ",
            json_output["RouterMAC"],
            end="",
            file=sample,
        )
        if json_output["Vendor"] != "":
            print(
                ", ", json_output["Vendor"], ", ", json_output["Country"], file=sample
            )
    # =================================================================================
    print("  Labels:", file=sample)
    if not json_output["Labels"]:
        print("    ---", file=sample)
    for i in json_output["Labels"]:
        if args.DNS == True:
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain, file=sample)
            except:
                print("    [", i["Label"], "] - ", i["Description"], file=sample)
        else:
            print("    [", i["Label"], "] - ", i["Description"], file=sample)
    # =================================================================================
    print("  DHCP:", file=sample)
    if not json_output["DHCP"]:
        print("    ---", file=sample)
    for i in json_output["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"], file=sample)
    # =================================================================================
    print("  Local Dependencies:", file=sample)
    if not json_output["LocalDependencies"]:
        print("    ---", file=sample)
    if args.LocalNumber != -1:
        tmp = 0
        for i in json_output["LocalDependencies"]:
            if tmp < args.LocalNumber:
                if i["Verb"] == "provides":
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                else:
                    print(
                        "    <- ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                tmp = tmp + 1
            else:
                break
    else:
        for i in json_output["LocalDependencies"]:
            if i["Verb"] == "provides":
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
            else:
                print(
                    "    <- ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
    # =================================================================================
    if not json_output["LocalStatistic"]:
        print("", file=sample)
    else:
        ip_address_statistics = {}
        for i in json_output["LocalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        print("  Print Local Statistic:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    # =================================================================================
    print("  Global Dependencies:", file=sample)
    if not json_output["GlobalDependencies"]:
        print("    ---", file=sample)
    if args.GlobalNumber == -1:
        for i in json_output["GlobalDependencies"]:
            if args.DNS == True:
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")]  Domain: ",
                        domain[0],
                        "  - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                except:
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
            else:
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
    else:
        tmp = 0
        for i in json_output["GlobalDependencies"]:
            if tmp < args.GlobalNumber:
                if args.DNS == True:
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                    except:
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                else:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                            file=sample,
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                            file=sample,
                        )
                tmp = tmp + 1
            else:
                break
    # =================================================================================
    if not json_output["GlobalStatistic"]:
        print("", file=sample)
    else:
        ip_address_statistics = {}
        for i in json_output["GlobalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        print("  Print Global Statistic:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)


def print_json(json_output, args):
    """Print safed analyze from JSON file. Into file or command line.

    Parameters
    -----------
    json_output : JSON
        JSON file loaded in python.        
    args : argparse
        Setted arguments of the script.
    """
    if args.print == True:
        for Dev in json_output["Devices"]:
            print_device_from_json(Dev, args)
    if args.file != "":
        if check_str(args.file, ".txt") == True:
            file = args.file
        else:
            file = args.file + ".txt"
        sample = open(file, "w")
        for Dev in json_output["Devices"]:
            print_device_to_file_from_json(Dev, args, sample)
