# Pintool for Backward-Edge CFI using shadow stacks

This implementation of Pintool creates shadow stacks for an application and uses it to detect
any violations of Backward-Edge CFI. To build and run the tool, refer to the following steps:

1. Extract all contents into <PIN_BASE_FOLDER>/sources/tools/. Make sure that the contents of
this folder are present in the same level as MyPinTool folder from the Pin examples.
2.  To build the pintool program "sanket_pintool_tls.cpp", run 
        
        make all

    This will create the sanket_pintool_tls.so file in obj-intel64/ folder.
    I am using scripts to run pin with this .so file.
    You can refer to the bash script in 'pintool' and 'exploit/pintool1'
    files.
    Note: The script only takes 4 arguments from cmd line, if you need to 
    test with more just add more args to the bash script.


3. Build the exploit code and helloWorld programs.

        cd exploit
        make all
        cd ../hello-World
        make all

4. To test pintool against different binaries, run ./pintool <binary_name>.
Implmented with multithreading, so we can check violations in complex
programs as well.

        cd <PIN_BASE_FOLDER>/sources/tools/Lab3_sanket_pintool
        ./pintool /bin/ls
        ./pintool /bin/gedit                # **
        ./pintool /bin/firefox              # ** 
        ./pintool /bin/vim
        ./pintool /bin/vim <filename>
        ./pintool /bin/cat <filename>
        ./pintool /bin/gedit <filename>     # **

    ** There are certain limitations with GTK based applications and pin.
    More information is provided in the pdf document.

5. To test pintool against hello-World program

        cd <PIN_BASE_FOLDER>/sources/tools/Lab3_sanket_pintool
        ./pintool hello-World/helloWorld
    
    It doesn't detect any violations, so the analysis report will be empty.

6. To test pintool against an exploit program. I am using return_to_helper 
and return_to_helper2
exploits from the exploit assignment.
The exploit and vuln programs are provided in 'exploit/' folder. 
Note: GRP_ID 917 is hardcoded for the program in the Makefile

        cd exploit
        make clean
        make all
        ./pintool1 ./driver1
        ./pintool1 ./driver2

Since the exploit program does a return_to_libc attack and modifies the
return arguments for auth, the pintool program will detect this attack.

You will see an output as below:


        =================================================================
        Thread ID: 0
                            Function Name |     Count
        -----------------------------------------------------------------
                                    auth|         1
                                    private_helper|         1
        =================================================================
        driver: Received '**** private_helper(0x1234567,
        0x123456789abcdef0, 0x7ffddd797058 "/bin/sh") called'
        ===
        Stack Smashing Detected in program
        Total mismatches detected :2
        vuln killed by signal 2