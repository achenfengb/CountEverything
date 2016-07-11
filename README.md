Count everything using homomorphic encyption
====

Requirement
---
JDK8 must be installed to run this program. The thep.jar lib is required.

Description
---
There are three classes (roles): data owner, cryptography service provider (CSP) and processor. All of them are in **Parties** package.
The data owner provide data for counting; the CSP provide the cryptography service and evaluate the ciphertext of final results; the processor collects the data from data owners in ciphtext form and process the data for CSP evaluation. Following are their constructor details.

1. DataOwner(String **CSPAddr**, String **ProcessorAddr**, int **CSPPort**, int **ProcessorPort**, int[] **IDsMask**, int **ThreadsNum**) 

2. CSP(int **CSPPort**, int **DataOwnersNum**, int **ThreadsNum**, int **BitsNum**)

3. Processor(String **CSPAddr**, int **CSPPort**, int **ProcessorPort**, int **DataOwnersNum**, int **ThreadsNum**)

**CSPAddr:**
the CSP IP address.

**ProcessorAddr**
the processor IP address.

**CSPPort**
the CSP listenning port.

**ProcessorPort**
the processor listenning port.

**IDsMask**
the mask of the global IDs. One ID Will be counted for this data owner if the corresponding value equals to 1; otherwise 0.

**ThreadsNum**
the number computation thread.

**DataOwnersNum**
the number of data owners. It should be equal to 3 under the current project.

**BitsNum**
the number of bits in plaintext space. it should >= 1024. 

call the **run()** function to start each party's protocol after intializing constructor. For example, to start one data ower's protocol, just

```
DataOwner data_owner = new DataOwner(String CSPAddr, String ProcessorAddr, int CSPPort, int ProcessorPort, int[] IDsMask, int ThreadsNum);
data_owner.run();
```

The final results are stored in CSP. One can call its member function **getResults()** to obtain the result in the form of integer array: 1 for counted; 0 for otherwise.

Contact
---
If you have any question or bug report, feel free to email me at *f4chen@ucsd.edu*.
