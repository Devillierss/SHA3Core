SHA3Core is a native C# dotnet core Implementation of Keccak, SHA3 and Shake

Overview

There are 3 separate classes that can be instantiated based on the algorithm you would like to use. These are SHA3, Keccak, and SHA3Shake.
Each of these can be created by passing the corresponding BitType to the class constructor. Each class contains a Hash method that can either accept a string or a byte[].

Usage

Create Instance of Algorithm Class
```csharp
var sha3 = new SHA3(SHA3BitType.S512);

Call Hash method

var result = sha3.Hash(InputMessage);
