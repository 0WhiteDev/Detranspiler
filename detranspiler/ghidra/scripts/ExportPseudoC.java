import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class ExportPseudoC extends ghidra.app.script.GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            printerr("Missing output file argument");
            return;
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        Pattern labPtr = Pattern.compile("&\\s*(LAB_[0-9A-Fa-f]+)");
        Set<String> labNames = new HashSet<>();

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function f = it.next();
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                    continue;
                }
                String c = res.getDecompiledFunction().getC();
                if (c == null || c.isEmpty()) {
                    continue;
                }

                Matcher mm = labPtr.matcher(c);
                while (mm.find()) {
                    String nm = mm.group(1);
                    if (nm != null && !nm.isEmpty()) {
                        labNames.add(nm);
                        if (labNames.size() >= 500) {
                            break;
                        }
                    }
                }
                out.println("/* FUNCTION " + f.getName() + " " + f.getEntryPoint().toString() + " */");
                out.println(c);
                out.println();
            }

            if (!labNames.isEmpty() && !monitor.isCancelled()) {
                FunctionManager fm = currentProgram.getFunctionManager();
                int extraCount = 0;
                for (String lab : labNames) {
                    if (monitor.isCancelled()) {
                        break;
                    }
                    if (lab == null || lab.isEmpty()) {
                        continue;
                    }
                    String hex = lab.substring(4);
                    long off;
                    try {
                        off = Long.parseUnsignedLong(hex, 16);
                    } catch (Exception e) {
                        continue;
                    }
                    Address addr = toAddr(off);
                    if (addr == null) {
                        continue;
                    }

                    Function f2 = fm.getFunctionAt(addr);
                    if (f2 == null) {
                        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
                        cmd.applyTo(currentProgram);
                        f2 = fm.getFunctionAt(addr);
                    }
                    if (f2 == null) {
                        continue;
                    }

                    try {
                        if (!lab.equals(f2.getName())) {
                            f2.setName(lab, SourceType.USER_DEFINED);
                        }
                    } catch (Exception e) {
                    }

                    DecompileResults res2 = ifc.decompileFunction(f2, 30, monitor);
                    if (res2 == null || !res2.decompileCompleted() || res2.getDecompiledFunction() == null) {
                        continue;
                    }
                    String c2 = res2.getDecompiledFunction().getC();
                    if (c2 == null || c2.isEmpty()) {
                        continue;
                    }

                    out.println("/* FUNCTION " + lab + " " + f2.getEntryPoint().toString() + " */");
                    out.println(c2);
                    out.println();
                    extraCount += 1;
                    if (extraCount >= 200) {
                        break;
                    }
                }
            }
        } finally {
            ifc.dispose();
        }
    }
}
