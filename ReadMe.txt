README

I have implemented all the exercises according to the instructions and the screenshots provided.

Only in unlock mode, instead of providing the shares in parentheses like ./antivirus unlock (1,5) (5,9) ... through the CLI, I provide them without parentheses as the parsing did not work for me.
for example ./antivirus unlock 1,5 5,9 ...

YARA Rule:

rule KozaliBear_Ransomware {
    meta:
        description = "YARA rule to detect KozaliBear ransomware attack"
        author = "Nikos Lefakis csd4804"
        
    strings:
        $malicious_library_md5 = "85578cd4404c6d586cd0ae1b36c98aca"
        $malicious_library_sha256 = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"
        $bitcoin_wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $virus_signature = { 98 1d 00 00 ec 33 ff ff fb 06 00 00 00 46 0e 10 }
        $ransomware_process = "*.locked" 
        
    condition:
        any of ($malicious_library_md5, $malicious_library_sha256, $bitcoin_wallet, $virus_signature, $ransomware_process)
}

The ARYA tool was not working for me, as it gave the following error:
Traceback (most recent call last):
  File "/usr/local/bin/arya", line 5, in <module>
    from arya import main
  File "/usr/local/bin/arya.py", line 440
    print processinputstr(inputstr, args)

I tried but couldn't find a solution. Instead, I simply ran:
yara -r kozalibear.yar testing/test.txt
KozaliBear_Ransomware testing/test.txt
to verify that some conditions of the rule are working.

Contact:
csd4804@csd.uoc.gr
