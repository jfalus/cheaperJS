# cheaperJS

Although I wasn't able to run the cheaper.py file correctly on my computer, I attempted to mimic its functionality in the js file here. It uses the same logic to parse the `cheaper.out` file as the `cheaper.py` file (which I verified by putting a lot of print statements in the `cheaper.py` file and making sure at each point my js code had the same values in its variables). This can be run by using the commands `npm install` and then ```node test.js --progname (Path to program Ex:swaptions) --jsonfile (Path to JSON file with trace Ex: cheaper.out)``` I want to work tomarrow to see if I can get the original `cheaper.py` to work, but for now this represents my progress.

## Updates

### 1/1/2021

Update cheaperJS with `execSync` to eliminate all promises. Also updated core functionality to mimic cheaper.py better. Still am unable to actually get the correct output when I run the program, but I suspect my issue is with the `swaptions` file as no memory addresses are found when calling `addr2line` for any of the addresses in `cheaper.out`
