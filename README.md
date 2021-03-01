# falcon-crowdstrike
## Indexes and Sourcetypes
There are many idexes available via splunk on crowdstrike besides main
* "main": main index with events described in Falcon Events;
* "aws_summary": empty;
* "cloud_usage_summary": empty;
* "cs_audit": empty;
* "eam_summary": host sensor state and info;
* "history": empty;
* "summary": agent heartbeat;
* "json": hardware status and detections;
* "detection_summary": empty;
* "discover_summary": five different types of events recorded (field name "search_name"):
  * Summary - Hash Usage - start of executables and Mac binaries;
  * Summary - Hash Written - different file write events;
  * Summary - Hourly Hash Usage - aggregated hash usage with number of hosts executed hash by hours, may be good to find unique hashes;
  * Summary - Module Loaded;
  * Summary - User Logon Activity.

## Interesting queries

Discover what file extesnions are logged with falcon sensor

```
index="discover_summary" AND search_name="Summary - Hash Written"
| eval FileName=lower(FileName)
| rex field=FileName ".*\.(?<extension>.*)"
| stats count by extension
```
File Statistics per Host and Attributes per File

* Put computer name in two places to search for files for exact host
* Filter on specific attributes e.g. Invokes Script Engine with adding | where InvokesScriptEng = "TRUE" at the end
* Filter on specific file path with adding | where match(ImageFileName,<regex>)
* Combine your filters at the end with AND statement
* Be patient, search is heavy and slow
* Available tags: CompanyName CreatesDir DeletesExec DeletesFiles DNSRequest EnumeratesDir ImageFileName InjectsDLL InjectsProc InjectsThread InvokesRunDll InvokesScriptEng LoadsUnsignedMod NetworkBinds NetworkConnects NetworkConnectsUDP NetworkListens OriginalFilename StratsService SuspDNSRequest SuspLoadsCredMod SuspReadsRAWDisk TakesScreenshot WritesArchives WritesBinExec WritesDocs WritesFiles

```
ComputerName=<name> event_simpleName=EndOfProcess
|  stats sum(DnsRequestCount_decimal) as DNSRequest, sum(NetworkBindCount_decimal) as NetworkBinds, sum(NetworkConnectCount_decimal) as NetworkConnects, sum(NetworkConnectCountUdp_decimal) as NetworkConnectsUDP, sum(NetworkListenCount_decimal) as NetworkListens, sum(InjectedDllCount_decimal) as InjectsDLL, sum(InjectedThreadCount_decimal) as InjectsThread, sum(ArchiveFileWrittenCount_decimal) as WritesArchives, sum(ExecutableDeletedCount_decimal) as DeletesExec, sum(FileDeletedCount_decimal) as DeletesFiles, sum(GenericFileWrittenCount_decimal) as WritesFiles, sum(DirectoryCreatedCount_decimal) as CreatesDir, sum(DirectoryEnumeratedCount_decimal) as EnumeratesDir, sum(DocumentFileWrittenCount_decimal) as WritesDocs, sum(BinaryExecutableWrittenCount_decimal) as WritesBinExec, sum(ScreenshotsTakenCount_decimal) as TakesScreenshot, sum(ScriptEngineInvocationCount_decimal) as InvokesScriptEng,sum(RunDllInvocationCount_decimal) as InvokesRunDll,sum(SetThreadContextCount_decimal) as InjectsProc, sum(ServiceEventCount_decimal) as StratsService, sum(SuspiciousCredentialModuleLoadCount_decimal) as SuspLoadsCredMod, sum(SuspiciousDnsRequestCount_decimal) as SuspDNSRequest,sum(UnsignedModuleLoadCount_decimal) as LoadsUnsignedMod, sum(SuspiciousRawDiskReadCount_decimal) as SuspReadsRAWDisk by SHA256HashData
| eval DNSRequest=if(DNSRequest>0, "TRUE", 0) | eval NetworkBinds=if(NetworkBinds>0, "TRUE", 0) | eval NetworkConnects=if(NetworkConnects>0, "TRUE", 0) |eval NetworkConnectsUDP=if(NetworkConnectsUDP>0, "TRUE", 0) |eval NetworkListens=if(NetworkListens>0, "TRUE", 0) |eval InjectsDLL=if(InjectsDLL>0, "TRUE", 0) |eval InjectsThread=if(InjectsThread>0, "TRUE", 0) |eval WritesArchives=if(WritesArchives>0, "TRUE", 0) |eval DeletesExec=if(DeletesExec>0, "TRUE", 0) |eval DeletesFiles=if(DeletesFiles>0, "TRUE", 0) |eval WritesFiles=if(WritesFiles>0, "TRUE", 0) |eval CreatesDir=if(CreatesDir>0, "TRUE", 0) |eval DeletesFiles=if(DeletesFiles>0, "TRUE", 0) |eval EnumeratesDir=if(EnumeratesDir>0, "TRUE", 0) |eval WritesDocs=if(WritesDocs>0, "TRUE", 0)|eval WritesBinExec=if(WritesBinExec>0, "TRUE", 0) |eval TakesScreenshot=if(TakesScreenshot>0, "TRUE", 0)|eval InvokesScriptEng=if(InvokesScriptEng>0, "TRUE", 0)|eval StratsService=if(StratsService>0, "TRUE", 0)|eval SuspLoadsCredMod=if(SuspLoadsCredMod>0, "TRUE", 0)|eval SuspDNSRequest=if(SuspDNSRequest>0, "TRUE", 0)|eval SuspReadsRAWDisk=if(SuspReadsRAWDisk>0, "TRUE", 0) | JOIN SHA256HashData type="left"
    [search ComputerName=<name> event_simpleName=ProcessRollup2 |  table SHA256HashData MD5HashData ImageFileName ]
| JOIN SHA256HashData type="left" [search event_simpleName=PeVersionInfo |  table SHA256HashData OriginalFilename CompanyName]
```
Different PE Filename and Original Filename

```
event_simpleName=PeVersionInfo
| eval FileName=lower(FileName)
| eval OriginalFilename=lower(OriginalFilename) | where FileName != OriginalFilename AND isnull(CompanyName)
| table FileName OriginalFilename FilePath
| dedup FileName OriginalFilename FilePath
```
LEFT JOIN (IF NULL) Process Start

Compare two hosts and display aggregated list of processes uniq for 1st host

```
ComputerName=<name> event_simpleName=ProcessRollUp2
|  table SHA256HashData, ImageFileName | JOIN SHA256HashData type="left" [search ComputerName=<name> AND event_simpleName=ProcessRollUp2]
|  where isnull(ComputerName)
|  table SHA256HashData, ImageFileName
|  dedup SHA256HashData, ImageFileName
|  stats list(ImageFileName) by SHA256HashData
```
INNER JOIN Process Start

Compare two hosts and display aggregated list of processes uniq for both hosts

```
ComputerName=<name> event_simpleName=ProcessRollUp2
|  table SHA256HashData, ImageFileName | JOIN SHA256HashData type="left" [search ComputerName=<name> AND event_simpleName=ProcessRollUp2]
|  where isnotnull(ComputerName)
|  table SHA256HashData, ImageFileName
|  dedup SHA256HashData, ImageFileName
|  stats list(ImageFileName) by SHA256HashData
```
Hash usage

Aggregated hash usage

```
index="discover_summary" AND search_name="Summary - Hourly Hash Usage"
| stats sum(HostCount) by SHA256HashData
| JOIN SHA256HashData type="left" [search event_simpleName=ProcessRollup2 |  table SHA256HashData ImageFileName ]
| where isnotnull(ImageFileName)
```
Searching events across specific OU\World Region

```
* | lookup aid_master.csv aid
| search OU=*Customer*
 
 
* | lookup aid_master.csv aid
| search Continent=Asia
```

Searching events across specific Crowdstrike group of hosts

```
* | lookup aid_policy.csv aid
| search groups=*089f0a2497db42a6931bf9f081414c48*
 
 
You can find group id in the URL if you click edit group in console https://falcon.crowdstrike.com/hosts/groups-new or in lookuptable group_info.csv
```
Searching for usage of generic built-in list of recon tools

```
event_simpleName=ProcessRoll*
    [| inputlookup cross_platform_recon_apps.csv | rename File as FileName
    |  rename FileName as search | format]
 
 
 
Combine with OU or groups
 
 
event_simpleName=ProcessRoll*
    [| inputlookup cross_platform_recon_apps.csv | rename File as FileName
    |  rename FileName as search | format] | lookup aid_master.csv aid
| search OU=*Customer*
```

## Interesting lookup tables
Please see full list on csv included
```
servers.csv - list of AIPs
managedassets.csv - Host info with geodata. May be used for narrowing search by region
userinfo.csv - accounts types, last logon time\host
appinfo.csv - PE header data
cross_platform_recon_apps.csv - recon apps
aid_policy.csv - policies and groups applied for host
aid_master.csv - hostnames description
detect_patterns.csv - all possible CS detections
group_info.csv - list of groups
```
Read lookup table
```
| inputlookup PolicyTag.csv
```
