'use strict';
const { ArgumentParser, RawTextHelpFormatter } = require('argparse');
const fs = require('fs');
const { exec } = require("child_process");

parse()

function parse() {
    const parser = new ArgumentParser({
        description: 'Cheaper: finds where you should use a custom heap.',
        prog: 'cheaper',
        formatter_class: RawTextHelpFormatter,
    });

    parser.add_argument('--progname', { help: 'path to executable', required: true });
    parser.add_argument('--jsonfile', { help: 'json to read', required: true });
    parser.add_argument('--threshold-mallocs', { help: 'threshold allocations to report', default: 100 });
    parser.add_argument('--threshold-score', { help: 'threshold reporting score', default: 0.8 });
    parser.add_argument('--skip', { help: 'number of stack frames to skip', default: 0 });
    parser.add_argument('--depth', { help: 'total number of stack frames to use (from top)', default: 5 });
    const args = parser.parse_args();
    if (args.progname === undefined)
        return -1;
    return runIt(args.jsonfile, args.progname, args.depth, args.threshold_mallocs, args.threshold_score);
}

//JS has no built in has function, so if I were to put a hash I would put it here
function hash(input) {
    return input;
}

function runIt(jsonfile, progname, depth, threshold_mallocs, threshold_score) {
    if (!fs.existsSync(jsonfile))
        return -2;
    fs.readFile(jsonfile, async (err, data) => {
        const trace = JSON.parse(data).trace;
        let analyzed = await process_trace(trace, progname, depth, threshold_mallocs, threshold_score);
        // Remove duplicates
        const dedup = {};
        analyzed.forEach(item => {
            if ("stack" in item) {
                const key = hash(JSON.stringify(item.stack));
                if (key in dedup) {
                    //Merge duplicate stacks
                    Array.prototype.push.apply(dedup[key].allocs, item.allocs);
                    item.sizes.forEach(size => dedup[key].sizes.add(size));
                    item.threads.forEach(thread => dedup[key].threads.add(thread));
                    // Recomputing region score = tricky...
                    // For now, use weighted average
                    if (dedup[key].allocs + item.allocs > 0) {
                        dedup[key].region_score = (
                            dedup[key].allocs * dedup[key].region_score
                            + item.allocs * item.allocs
                        ) / (dedup[key].allocs + item.allocs);
                    } else {
                        dedup[key].region_score = 0;
                    }
                } else {
                    dedup[key] = item;
                }
            }
        })
        analyzed = Object.values(dedup);
        //Sort in reverse order by region score * number of allocations
        analyzed = analyzed.sort((a, b) => (b.region_score * b.allocs) - (a.region_score * a.allocs));
        analyzed.forEach(item => {
            item.stack.forEach(stk => console.log(stk));
            console.log("-----");
            console.log("region score = ", item.region_score);
            console.log("number of allocs = ", item.allocs);
            console.log("sizes = ", item.sizes);
            console.log("threads = ", item.threads);
            console.log("=====");
        })
    });
}

async function process_trace(trace, progname, depth, threshold_mallocs, threshold_score) {
    let stack_series = {};
    const stack_info = {};
    // Convert each stack frame into a name and line number
    trace.forEach(async i => {
        i.stack.slice(-depth).forEach(async stkaddr => {
            if (!(stkaddr in stack_info)) {
                stack_info[stkaddr] = new Promise((resolve, reject) => {
                    exec("addr2line 0x" + stkaddr.toString(16) + " -C -e " + progname, 
                    (error, stdout, stderr) => {
                        const temp = {};
                        temp[stkaddr] = stdout.replace(/^\s+|\s+$/gm, '');
                        resolve(temp);
                    })
                });
            }
        })
    })
    return Promise.all(Object.values(stack_info))
        .then(x => {
            const new_stack_info = x.reduce((a, e) => Object.assign(a, e), {});
            // Separate each trace by its complete stack signature.
            trace.forEach(i => {
                const stk = i.stack.slice(-depth).map(k => new_stack_info[k]); //[skip:depth+skip]]
                const stkstr = "['" + stk.join("', '") + "']";
                if (!Array.isArray(stack_series[stkstr])) stack_series[stkstr] = [];
                stack_series[stkstr].push(i);
            })
            // Iterate through each call site.
            const analyzed = [];
            for (let d = 0; d < depth; d++) {
                Object.keys(stack_series).forEach(k => {
                    analyzed.push(analyze(stack_series[k], k, progname, d, threshold_mallocs, threshold_score));
                })
            }
            return analyzed;
        })

}

function analyze(allocs, stackstr, progname, depth, threshold_mallocs, threshold_score) {
    //Analyze a trace of allocations and frees.
    const analyzed_list = [];
    if (allocs.length < parseInt(threshold_mallocs))
        //Ignore call sites with too few mallocs
        return analyzed_list;
    //The set of sizes of allocated objects.
    const sizes = new Set();
    //A histogram of the # of objects allocated of each size.
    const size_histogram = {};
    let actual_footprint = 0; //mallocs - frees
    let peak_footprint = 0; //max actual_footprint
    let peak_footprint_index = 0; //index of alloc w/max footprint
    let nofree_footprint = 0; //sum(mallocs)
    //set of all thread ids used for malloc/free
    const tids = new Set();
    //set of all (currently) allocated objects from this site
    const mallocs = new Set();
    let num_allocs = 0;
    const utilization = 0;
    allocs.forEach((i, index) => {
        sizes.add(i.size);
        size_histogram[i.size]++;
        tids.add(i.tid);
        if (i.action === 'M') {
            num_allocs++;
            //Compute actual footprint (taking into account mallocs and frees).
            actual_footprint += i.size;
            if (actual_footprint > peak_footprint) {
                peak_footprint = actual_footprint;
                peak_footprint_index = index;
            }
            // Compute total 'no-free' memory footprint (excluding frees) This
            // is how much memory would be consumed if we didn't free anything
            // until the end (as with regions/arenas). We use this to compute a
            // "region score" later.
            nofree_footprint += i.size;
            // Record the malloc so we can check it when freed.
            mallocs.add(i.address);
        } else if (i.action === 'F') {
            if (mallocs.has(i.address)) {
                // Only reclaim memory that we have already allocated
                // (others are frees to other call sites).
                actual_footprint -= i.size;
                mallocs.delete(i.address);
            } else {
                // print(mallocs)
                // print(str(i["address"]) + " not found")
            }
        }
    })
    // Recompute utilization
    // frag = Cheaper.utilization(allocs, peak_footprint_index)
    // Compute entropy of sizes
    const total = allocs.length;
    const normalized_entropy = -Object.keys(size_histogram).reduce((a, e) =>
        (e / total * Math.log2(e / total)) + a
    ) / size_histogram.length;
    // Compute region_score (0 is worst, 1 is best - for region replacement).
    let region_score = 0;
    if (nofree_footprint != 0)
        region_score = peak_footprint / nofree_footprint;
    if (region_score >= threshold_score) {
        const stk = eval(stackstr);
        const output = {
            "stack": stk,
            "allocs": num_allocs,
            "region_score": region_score,
            "threads": tids,
            "sizes": sizes,
            "size_entropy": normalized_entropy,
            "peak_footprint": peak_footprint,
            "nofree_footprint": nofree_footprint,
        };
        analyzed_list.push(output);
    }
    return analyzed_list;
}