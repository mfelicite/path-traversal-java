package com.codd.pathtraversal;


import java.io.IOException;
import java.nio.file.Path;

public class App {

    private final Path baseDir;

    public App(Path baseDir) {
        this.baseDir = baseDir.toAbsolutePath();
    }

    public boolean isAllowedVulnerableString(String userInput) {
        Path target = baseDir.resolve(userInput).normalize();
        return target.toString().startsWith(baseDir.toString());
    }

    public boolean isAllowedVulnerableNormalize(String userInput) {
        Path target = baseDir.resolve(userInput).normalize();
        return target.startsWith(baseDir);
    }

    public boolean isAllowedSecure(String userInput) {
        try {
            Path realBase = baseDir.toRealPath();
            Path realTarget = realBase.resolve(userInput).toRealPath();
            return realTarget.startsWith(realBase);
        } catch (IOException e) {
            return false;
        }
    }
}
