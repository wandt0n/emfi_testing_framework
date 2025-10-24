This framework automates electromagnetic fault injection tests. It uses a Textual UI to allow for easy setup, monitoring, and interaction while runnning. While it was designed to work with the NewAE ChipShouter and ThorLabs motors, it can be easily adapted due to hardware abstractions and OOP. 

The header of the python file contains instructions on how to use it.

## Safety
Performing EMFI may involve moving parts and high voltages. Both can harm you, your target, and test equipment. The emergency stop feature of this framework (pressing the "e" key twice in succession) should stop all motors immediately and disarm the ChipShouter. HOWEVER, it is not meant as a replacement for a proper, hardware emergency stop! The software e-stop may not work in some scenarios and is not even present in all UI screens. Ensure that you take appropriate safety precautions for you and your hardware. Additionally:
 - Keep a distance to the experiment setup whenever the motors or fault injector are plugged in. Ensure that others do the same
 - Convince yourself that the motors behave as expected throughout the script's runtime before attaching anything to them

## Adapt to Your Setup
_If you adapt it, test your setup using the command line options and included Dummy classes to emulate hardware behavior._

If you want to use other motors, check whether they are supported by the pylablib module. If not, write an addition to said module or change the move() function and the few other routines that access "axes.items()" accordingly. If you want to use other fault injectors, adapt the CS_Connector class.
This framework is designed around faulting an RSA #PKCS1v1.5 signature. If you want to target other processes, you can write a corresponding routine and add its handle with a keyword to the KEYWORD_HANDLERS dictionary. The framework will pass received messages to that routine if it receives the registered keyword. This requires you to implement some routine on the target that sends transmissions accoringly to the following BNF grammar:
```bnf
<transmission> ::= <keyword> ":" "\r\n" <prefix> <message> "\r\n"
<keyword>      ::= <ascii-text>
<prefix>       ::= "\x01\xfe\x01\xfe" | ""
<message>      ::= <list> | <binary-data> | <ascii-text>
<list>         ::= <ascii-text> ", " | <ascii-text> ", " <list>
```
If you can't modify the target's firmware or do not want to use this grammar, you may need to rework the worker_loop() function of the LabControl class and the listen() function of the SerialTarget class. If your experiment requires the detection of resets, you may reuse the reset detection mechanism that this framework already incorporates.

## Licensing
You may use and modify this framework for legal purposes, see the attached MIT Licence. If you publish a modified version of it, please reference this repository. If you publish results in academia that were obtained by using my framework or a modified version of it, I encourage you to cite the following master thesis (although it will not be made available to the public, unfortunately):
```
@mastersthesis{kettling_2025_emfi,
  title        = {Evaluation of Countermeasures against Semi Invasive Attacks on Automotive Microcontrollers},
  author       = {Anton Kettling},
  year         = 2025,
  school       = {Ruhr-University Bochum}
}
``` 

