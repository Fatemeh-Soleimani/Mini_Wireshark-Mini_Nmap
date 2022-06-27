from tcp_syn_sender import *

ip = input("what is the terget ip address?")
ports = input("which ports do you want to scan?")

# range
x = ports.split("-")

# change ip in info.txt file
a_file = open("info.txt", "r")
list_of_lines = a_file.readlines()
ip += "\n"
list_of_lines[0] = ip

a_file = open("info.txt", "w")
a_file.writelines(list_of_lines)
a_file.close()


temp = ""

for i in range(x[0], x[1]):
    # change port in info.txt file
    a_file = open("info.txt", "r")
    list_of_lines = a_file.readlines()
    temp = str(i)
    temp += "\n"
    list_of_lines[1] = temp

    a_file = open("info.txt", "w")
    a_file.writelines(list_of_lines)
    a_file.close()

    main_()
