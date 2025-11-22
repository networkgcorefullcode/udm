package milenage256_test

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/omec-project/udm/milenage256"
)

func TestMilenage256_TestCase4d_Concurrency(t *testing.T) {
	// --- DATOS DEL TEST CASE #4d ---
	keyHex := "aff1951a2a5149caf59d9e5fc5c5995473536ba65a41f744010e8fc1fa11fe4d"
	opHex := "3d5f059e24d37533f7dd09a1745afdc256229951c0ddb459df1977edcc9a631a" // Corregido (sin el 5 extra)
	randHex := "090ccce38904bdc40c509b2342f13522"
	sqnHex := "dc1498b4d7bd"
	amfHex := "93d7"

	// Valores esperados (Output)
	wantOPc := "b5a3105ad5a3188cc59cb46690a4df298339213d16b24c73f52c654fb0367cf6"
	wantMacS := "a2f062a6ee181e24"
	wantMacA := "9c79c4a45b771187"
	wantRes := "aedd7ff35e1375f6"
	wantCk := "b7cb9b55d17bd311b64da411f6513ea5f1fff5795bfd91a5d463f18704c26178"
	wantIk := "7f095b8fd8f7e501ff52d8994d294e9368f02e2db0d61adb15ae695809fcf482"
	wantAk := "fccd9c204f14"
	wantAkS := "ac87e03428b2"

	// Decodificar inputs
	key, _ := hex.DecodeString(keyHex)
	op, _ := hex.DecodeString(opHex)
	rand, _ := hex.DecodeString(randHex)
	sqn, _ := hex.DecodeString(sqnHex)
	amf, _ := hex.DecodeString(amfHex)

	// Configurar parámetros
	config := milenage256.DefaultConfig()
	copy(config.OP[:], op)
	// Ajustes específicos del Caso 4d
	config.ResSize = 8
	config.MacSize = 8
	config.AkSize = 6

	// --- PRUEBA DE CONCURRENCIA ---
	// Vamos a lanzar 100 goroutines simultáneas calculando lo mismo.
	// Si hay condiciones de carrera (variables globales), los resultados variarán o el programa crasheará.

	var wg sync.WaitGroup
	routines := 100

	for i := 0; i < routines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 1. Verificar OPc
			opc := milenage256.ComputeOPc(config, key)
			if hex.EncodeToString(opc[:]) != wantOPc {
				t.Errorf("Goroutine %d: OPc incorrecto. Got: %x", id, opc)
				return
			}

			// 2. Generar Vectores
			macA, macS, res, ck, ik, ak, akStar := milenage256.GenerateAuthenticationVectors(config, key, rand, sqn, amf)

			// Comparar resultados
			check(t, id, "MAC-A", macA, wantMacA)
			check(t, id, "MAC-S", macS, wantMacS)
			check(t, id, "RES", res, wantRes)
			check(t, id, "CK", ck, wantCk)
			check(t, id, "IK", ik, wantIk)
			check(t, id, "AK", ak, wantAk)
			check(t, id, "AK*", akStar, wantAkS)
		}(i)
	}

	wg.Wait()
	fmt.Println("Prueba de concurrencia finalizada exitosamente.")
}

func check(t *testing.T, id int, name string, got []byte, wantHex string) {
	gotHex := hex.EncodeToString(got)
	if gotHex != wantHex {
		t.Errorf("Goroutine %d: %s mismatch.\nGot:  %s\nWant: %s", id, name, gotHex, wantHex)
	}
}

// Test simple para ver solo los valores (como tu ejemplo anterior)
func TestMilenage256_SingleRun(t *testing.T) {
	key, _ := hex.DecodeString("aff1951a2a5149caf59d9e5fc5c5995473536ba65a41f744010e8fc1fa11fe4d")
	op, _ := hex.DecodeString("3d5f059e24d37533f7dd09a1745afdc256229951c0ddb459df1977edcc9a631a")
	rand, _ := hex.DecodeString("090ccce38904bdc40c509b2342f13522")
	sqn, _ := hex.DecodeString("dc1498b4d7bd")
	amf, _ := hex.DecodeString("93d7")

	cfg := milenage256.DefaultConfig()
	copy(cfg.OP[:], op)
	cfg.ResSize = 8
	cfg.MacSize = 8
	cfg.AkSize = 6

	opc := milenage256.ComputeOPc(cfg, key)
	macA, _, res, ck, ik, ak, _ := milenage256.GenerateAuthenticationVectors(cfg, key, rand, sqn, amf)

	fmt.Printf("=== Resultados Single Run ===\n")
	fmt.Printf("OPc: %x\n", opc)
	fmt.Printf("MAC-A: %x\n", macA)
	fmt.Printf("RES: %x\n", res)
	fmt.Printf("CK: %x\n", ck)
	fmt.Printf("IK: %x\n", ik)
	fmt.Printf("AK: %x\n", ak)
}
