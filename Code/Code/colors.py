from colorama import init,Fore,Back,Style
import os

# this file is for the printing color in the brutal_SSH file
#
# colors in unit oparetion system
if os.name == "posix":
    # colors foreground text:
    fw = "\033[0;97m"
    fm = "\033[0;35m"
    fr = "\033[0;91m"
    fc = "\033[0;96m"
    fg = "\033[0;92m"
    fb = "\033[0;94m"
    fy = "\033[0;33m"
    ff = Fore.RESET
    # colors background text:
    bw = "\033[47m"
    br = "\033[41m"
    by = "\033[43m"
    bg = "\033[42m"
    bc = "\033[46m"
    bb = "\033[44m"
    bm = "\033[45m"
    bf = Back.RESET
    # colors style text:
    sn = Style.NORMAL
    sb = Style.BRIGHT
    sf = Style.RESET_ALL


fgb = fg + sb       #foreground green bright style
fbb = fb + sb       #foreground blue bright style
fyb = fy + sb       #foreground yellow bright style
fcb = fc + sb       #foreground cyan bright style
frb = fr + sb       #foreground red bright style
fwb = fw + sb       #foreground white bright style
fmb = fm + sb       #foreground magenta bright style
ffb = ff + sb       #foreground reset bright style


#colors according to the output types
info_out = fgb + "[V] "
gen_info = fyb + "[=] "
ver_out = frb + "[X] "
err_out = fbb + "[E] "
