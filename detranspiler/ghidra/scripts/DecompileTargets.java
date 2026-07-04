import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class DecompileTargets extends ghidra.app.script.GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            printerr("Expected target-list and output paths");
            return;
        }
        File targetFile = new File(args[0]);
        File outputFile = new File(args[1]);
        File parent = outputFile.getParentFile();
        if (parent != null) parent.mkdirs();
        FunctionManager manager = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (BufferedReader input = new BufferedReader(new InputStreamReader(new FileInputStream(targetFile), StandardCharsets.US_ASCII));
             PrintWriter output = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null && !monitor.isCancelled()) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length != 2) continue;
                Address address;
                try { address = toAddr(Long.parseUnsignedLong(fields[1], 16)); }
                catch (Exception error) { continue; }
                if (address == null || manager.getFunctionContaining(address) != null) continue;
                CreateFunctionCmd create = new CreateFunctionCmd(address);
                if (!create.applyTo(currentProgram)) continue;
                Function target = manager.getFunctionAt(address);
                if (target == null) continue;
                DecompileResults result = decompiler.decompileFunction(target, 60, monitor);
                if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) continue;
                String code = result.getDecompiledFunction().getC();
                if (code == null || code.isEmpty()) continue;
                output.println("/* FUNCTION " + fields[0] + "__cff_" + fields[1] + " " + address.toString() + " */");
                output.println(code);
                output.println();
            }
        } finally {
            decompiler.dispose();
        }
    }
}
