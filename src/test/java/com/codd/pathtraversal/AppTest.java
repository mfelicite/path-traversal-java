package com.codd.pathtraversal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("Démonstration CWE-22 : Traversée de chemin (Java NIO)")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AppTest {

    @TempDir
    static Path tempRoot;

    private static App service;
    private static Path dataDir;
    private static Path outsideSecret;

    @BeforeAll
    static void setUp() throws IOException {
        dataDir = Files.createDirectory(tempRoot.resolve("data"));
        Path secretDir = Files.createDirectory(tempRoot.resolve("data-secret"));

        Files.writeString(dataDir.resolve("public.txt"), "Contenu public");
        Files.writeString(secretDir.resolve("secret.txt"), "Secret dossier voisin");
        outsideSecret = Files.writeString(tempRoot.resolve("system_secret.txt"), "Secret système");

        Files.createSymbolicLink(dataDir.resolve("lien_piege.txt"), outsideSecret);

        service = new App(dataDir);
    }

    @Test
    @Order(1)
    @DisplayName("1. Cas nominal : accès légitime dans /data autorisé")
    void testValidAccess() {
        assertTrue(service.isAllowedSecure("public.txt"));
    }

    @Test
    @Order(2)
    @DisplayName("2. Piège 1 : String.startsWith() trompé par /data-secret")
    void testStringComparisonTrap() {
        String payload = "../data-secret/secret.txt";
        assertTrue(service.isAllowedVulnerableString(payload), "La comparaison String est contournée");
        assertFalse(service.isAllowedSecure(payload), "Path.startsWith() bloque l'évasion");
    }

    @Test
    @Order(3)
    @DisplayName("3. Piège 2 : normalize() seul trompé par un lien symbolique")
    void testSymlinkTrap() {
        String payload = "lien_piege.txt";
        assertTrue(service.isAllowedVulnerableNormalize(payload), "normalize() ignore le symlink");
        assertFalse(service.isAllowedSecure(payload), "toRealPath() résout et bloque le symlink");
    }

    @AfterAll
    static void printSummaryTable() {

        System.out.println("\n" + "\u001B[1m" + "\u001B[36m" + "=== RÉSULTATS DE LA DÉMO : TRAVERSÉE DE CHEMIN (CERT FIO16-J) ===" + "\u001B[0m");
        System.out.println("Répertoire autorisé : " + dataDir);
        System.out.println("Lien symbolique     : lien_piege.txt -> " + outsideSecret + "\n");

        String fmt = "%-28s | %-20s | %-20s | %-20s%n";
        System.out.printf("\u001B[1m" + fmt + "\u001B[0m", "ENTRÉE UTILISATEUR", "1. String.startsWith", "2. normalize() seul", "3. toRealPath()");
        System.out.println("-".repeat(94));

        record Case(String payload, boolean expected) {}
        List<Case> cases = List.of(
            new Case("public.txt", true),
            new Case("../data-secret/secret.txt", false),
            new Case("lien_piege.txt", false),
            new Case("../../etc/passwd", false)
        );

        for (Case c : cases) {
            String r1 = format(service.isAllowedVulnerableString(c.payload), c.expected);
            String r2 = format(service.isAllowedVulnerableNormalize(c.payload), c.expected);
            String r3 = format(service.isAllowedSecure(c.payload), c.expected);
            System.out.printf(fmt, c.payload, r1, r2, r3);
        }
        System.out.println("-".repeat(94) + "\n");
    }

    private static String format(boolean actual, boolean expected) {
        if (actual == expected) {
            return "\u001B[32m" + (actual ? "✅ AUTORISÉ" : "✅ BLOQUÉ") + "\u001B[0m";
        }
        return "\u001B[31m" + (actual ? "❌ CONTOURNÉ !" : "❌ BLOQUÉ") + "\u001B[0m";
    }
}
