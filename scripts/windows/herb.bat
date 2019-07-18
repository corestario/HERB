@echo off
set user=%1
set privateKey=%2
set id=%3
set commonkey=0452b4a6d7883102258a87539c41898cd1c78bcc27dd905d9111e8b066504ba31b160580530886a2200833c2281e10377dbb2007abc531959a23df365ffc16ee18
set stage="stageUnstarted"
set round=0
cd C:/go-path/bin
@timeout /t 7 >nul
:mainloop
echo Current round is:
hcli query herb current-round
echo.
set START=%Time%
for /f "delims=" %%a in ('hcli query herb current-round') do @set currentround=%%a
REM ciphertext collecting
echo ct-part sending...
:ct_part_sending
@timeout /t 1 >nul
echo alicealice | hcli tx herb ct-part %commonkey% -y --from %user% >nul || goto :ct_part_sending 
REM waiting for decryption stage
echo next stage waiting...
:wait_ds_collecting
for /f "delims=" %%a in ('hcli query herb stage') do @set stage=%%a
@timeout /t 1 >nul
if NOT %stage%==stageDSCollecting (goto :wait_ds_collecting)
REM Decryption shares collecting
echo decryption share sending...
:ds_collecting
@timeout /t 1 >nul
echo alicealice | hcli tx herb decrypt %privateKey% %id% -y --from %user% >nul || goto :ds_collecting
REM waiting for the round result
echo waiting for all shares...
:wait_results
@timeout /t 1 >nul
for /f "delims=" %%a in ('hcli query herb stage') do @set stage=%%a
for /f "delims=" %%a in ('hcli query herb current-round') do @set round=%%a
if %stage%==stageCtCollecting (
	if NOT %round%==%currentround% (goto :end_wiat_results)
) else (
	goto :wait_results
)
:end_wiat_results
REM waiting new round
echo end round waiting...
:wait_new_round
@timeout /t 1 >nul
for /f "delims=" %%a in ('hcli query herb current-round') do @set round=%%a
if %round%==%currentround% (goto :wait_new_round)
set END=%Time%
set DIFF=%START% - %END%
echo The result is:
hcli query herb get-random %currentround%
echo.
echo It took:
echo %DIFF%
echo.
goto :mainloop