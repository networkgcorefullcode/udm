// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"

	"github.com/antihax/optional"
	ssm_const "github.com/networkgcorefullcode/ssm/const"
	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/Nudr_DataRepository"
	"github.com/omec-project/openapi/models"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/keydecrypt"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/milenage256"
	"github.com/omec-project/udm/service/health"
	"github.com/omec-project/udm/ssm/apiclient"
	"github.com/omec-project/udm/util"
	"github.com/omec-project/util/httpwrapper"
	"github.com/omec-project/util/milenage"
	"github.com/omec-project/util/ueauth"
	"github.com/omec-project/util/util_3gpp/suci"
)

const (
	SqnMAx    int64 = 0xFFFFFFFFFFFF
	ind       int64 = 32
	keyStrLen int   = 32
	opStrLen  int   = 32
	opcStrLen int   = 32
)

const (
	authenticationRejected string = "AUTHENTICATION_REJECTED"
)

func aucSQN(opc, k, auts, rand []byte) ([]byte, []byte) {
	AK, SQNms := make([]byte, 6), make([]byte, 6)
	macS := make([]byte, 8)
	ConcSQNms := auts[:6]
	AMF, err := hex.DecodeString("0000")
	if err != nil {
		return nil, nil
	}

	logger.UeauLog.Debugln("ConcSQNms", ConcSQNms)

	err = milenage.F2345(opc, k, rand, nil, nil, nil, nil, AK)
	if err != nil {
		logger.UeauLog.Errorln("milenage F2345 err ", err)
	}

	for i := 0; i < 6; i++ {
		SQNms[i] = AK[i] ^ ConcSQNms[i]
	}

	err = milenage.F1(opc, k, rand, SQNms, AMF, nil, macS)
	if err != nil {
		logger.UeauLog.Errorln("milenage F1 err", err)
	}

	logger.UeauLog.Debugln("SQNms", SQNms)
	logger.UeauLog.Debugln("macS", macS)
	return SQNms, macS
}

func strictHex(s string, n int) string {
	l := len(s)
	if l < n {
		return fmt.Sprint(strings.Repeat("0", n-l) + s)
	} else {
		return s[l-n : l]
	}
}

func HandleGenerateAuthDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UeauLog.Infoln("handle GenerateAuthDataRequest")
	authInfoRequest := request.Body.(models.AuthenticationInfoRequest)
	supiOrSuci := request.Params["supiOrSuci"]
	response, problemDetails := GenerateAuthDataProcedure(authInfoRequest, supiOrSuci)
	if response != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleConfirmAuthDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UeauLog.Infoln("Handle ConfirmAuthDataRequest")

	authEvent := request.Body.(models.AuthEvent)
	supi := request.Params["supi"]

	problemDetails := ConfirmAuthDataProcedure(authEvent, supi)

	if problemDetails != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		stats.IncrementUdmUeAuthenticationStats("create", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusCreated, nil, nil)
	}
}

func ConfirmAuthDataProcedure(authEvent models.AuthEvent, supi string) (problemDetails *models.ProblemDetails) {
	var createAuthParam Nudr_DataRepository.CreateAuthenticationStatusParamOpts
	optInterface := optional.NewInterface(authEvent)
	createAuthParam.AuthEvent = optInterface

	client, err := createUDMClientToUDR(supi)
	if err != nil {
		return util.ProblemDetailsSystemFailure(err.Error())
	}
	resp, err := client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(
		context.Background(), supi, &createAuthParam)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: int32(resp.StatusCode),
			Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("[ConfirmAuth]", err.Error())
		return problemDetails
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UeauLog.Errorf("CreateAuthenticationStatus response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

func GenerateAuthDataProcedure(authInfoRequest models.AuthenticationInfoRequest, supiOrSuci string) (
	response *models.AuthenticationInfoResult, problemDetails *models.ProblemDetails,
) {
	logger.UeauLog.Debugln("in GenerateAuthDataProcedure")

	response = &models.AuthenticationInfoResult{}
	supi, err := suci.ToSupi(supiOrSuci, udm_context.UDM_Self().SuciProfiles)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("suciToSupi error:", err.Error())
		return nil, problemDetails
	}

	logger.UeauLog.Debugf("supi conversion => %s", supi)

	client, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}
	authSubs, res, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(context.Background(), supi, nil)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("return from UDR QueryAuthSubsData error")
		return nil, problemDetails
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryAuthSubsData response body cannot close: %+v", rspCloseErr)
		}
	}()

	/*
		K, RAND, CK, IK: 128 bits (16 bytes) (hex len = 32)
		SQN, AK: 48 bits (6 bytes) (hex len = 12) TS33.102 - 6.3.2
		AMF: 16 bits (2 bytes) (hex len = 4) TS33.102 - Annex H
	*/

	hasK, hasOP, hasOPC := false, false, false

	var kStr, opStr, opcStr string

	k, op, opc := make([]byte, 16), make([]byte, 16), make([]byte, 16)

	logger.UeauLog.Debugln("K", k)

	if authSubs.PermanentKey != nil {
		encryptedKiHex := authSubs.PermanentKey.PermanentKeyValue
		encryptionKeyHex := authSubs.PermanentKey.EncryptionKey

		switch {
		case udm_context.UDM_Self().SsmEnable:

			if health.ReadStopCondition() {
				problemDetails = &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: "Service stop condition triggered",
				}
				return nil, problemDetails
			}
			// If SSM is enabled and there is an encryption key, use the SSM service to decrypt.
			logger.UeauLog.Debugln("EncryptionKey is present, calling SSM to decrypt PermanentKeyValue.")

			// 1. Configure the SSM client
			ssmClient := apiclient.GetSSMAPIClient()

			// 2. Prepare the decryption request
			encryptionAlgorithm := int(authSubs.PermanentKey.EncryptionAlgorithm)
			keyLabel, ok := ssm_const.AlgorithmLabelMap[encryptionAlgorithm]
			if !ok {
				problemDetails = &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: fmt.Sprintf("Unsupported encryption algorithm: %d", encryptionAlgorithm),
				}
				logger.UeauLog.Errorf("Unsupported encryption algorithm: %d", encryptionAlgorithm)
				return nil, problemDetails
			}

			keyId := authSubs.K4_SNO

			// 3. Check if decrypt is AESGCM
			if authSubs.PermanentKey.Tag != "" && authSubs.PermanentKey.IV != "" && authSubs.PermanentKey.Aad != "" {

				kStr, problemDetails = keydecrypt.DecryptSSMAESGCM(authSubs.PermanentKey.PermanentKeyValue, authSubs.PermanentKey.IV, authSubs.PermanentKey.Tag, authSubs.PermanentKey.Aad, keyLabel, int32(keyId), ssmClient)
			} else {
				// Use standard decryption
				kStr, problemDetails = keydecrypt.DecryptSSM(authSubs.PermanentKey.PermanentKeyValue, authSubs.PermanentKey.IV, keyLabel, int32(encryptionAlgorithm), int32(keyId), ssmClient)
			}
			if problemDetails != nil {
				return nil, problemDetails
			}

		case udm_context.UDM_Self().VaultEnable:
			if health.ReadStopCondition() {
				problemDetails = &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: "Service stop condition triggered",
				}
				return nil, problemDetails
			}
			// If SSM is enabled and there is an encryption key, use the SSM service to decrypt.
			logger.UeauLog.Debugln("EncryptionKey is present, calling Vault Secret Transit to decrypt PermanentKeyValue.")

			kStr, problemDetails = keydecrypt.DecryptVault(encryptedKiHex, authSubs.PermanentKey.Aad, keydecrypt.InternalKeyLabel)

			if problemDetails != nil {
				return nil, problemDetails
			}

		case encryptionKeyHex == "" && authSubs.PermanentKey.EncryptionAlgorithm == 0:
			// If there is no encryption key, we assume that the permanent key is not encrypted.
			logger.UeauLog.Debugln("EncryptionKey is empty, using PermanentKeyValue as is.")
			kStr = encryptedKiHex

		default:
			// If SSM is not enabled but there is an encryption key, proceed to decrypt locally.
			logger.UeauLog.Debugln("EncryptionKey is present, decrypting PermanentKeyValue locally.")
			decryptedKiHex, decryptErr := keydecrypt.DecryptKi(encryptedKiHex, encryptionKeyHex)
			if decryptErr != nil {
				problemDetails = &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: fmt.Sprintf("Failed to decrypt PermanentKey: %s", decryptErr.Error()),
				}
				logger.UeauLog.Errorf("PermanentKey decryption failed: %+v", decryptErr)
				return nil, problemDetails
			}
			kStr = decryptedKiHex
		}

		if len(kStr) == keyStrLen || len(kStr) == 64 { // Acepta 32 O 64 caracteres{
			k, err = hex.DecodeString(kStr) // aqui quiero que rectifiques si tambien si el tamano es de 64 caracteres hexagesimales que serian los 32 bytes que tendria una llave ki  para milenage 256 o sea puede ser de 32 caracteres hex para milenage clasico 128 o 64
			if err != nil {
				logger.UeauLog.Errorln("err", err)
			} else {
				hasK = true
			}
		} else {
			problemDetails = &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
			}

			logger.UeauLog.Errorln("kStr length is", len(kStr))
			return nil, problemDetails
		}
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
		}

		logger.UeauLog.Errorln("Nil PermanentKey")
		return nil, problemDetails
	}

	if authSubs.Milenage != nil {
		if authSubs.Milenage.Op != nil {
			opStr = authSubs.Milenage.Op.OpValue
			if len(opStr) == opStrLen || len(opStr) == 64 { // Acepta 32 O 64 caracteres{ // aqui igual la llave op puede tener 64 caracteres hex o lo q es lo mismo 32 bytes
				op, err = hex.DecodeString(opStr)
				if err != nil {
					logger.UeauLog.Errorln("err", err)
				} else {
					hasOP = true
				}
			} else {
				logger.UeauLog.Errorln("opStr length is", len(opStr))
			}
		} else {
			logger.UeauLog.Infoln("Nil Op")
		}
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
		}

		logger.UeauLog.Infoln("Nil Milenage")
		return nil, problemDetails
	}

	if authSubs.Opc != nil && authSubs.Opc.OpcValue != "" {
		opcStr = authSubs.Opc.OpcValue
		if len(opcStr) == opcStrLen || len(opcStr) == 64 { // Acepta 32 O 64 caracteres // aqui tb lo mismo de los tamanos o sea puede ser de 32 o 64
			opc, err = hex.DecodeString(opcStr)
			if err != nil {
				logger.UeauLog.Errorln("err", err)
			} else {
				hasOPC = true
			}
		} else {
			logger.UeauLog.Errorln("opcStr length is", len(opcStr))
		}
	} else {
		logger.UeauLog.Infoln("Nil Opc")
	}

	if !hasOPC && !hasOP {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
		}

		return nil, problemDetails
	}

	if !hasOPC {
		if hasK && hasOP {
			if len(k) == 32 {
				// Milenage256: Compute OPc using 256-bit logic
				cfg := milenage256.DefaultConfig()
				opcArray := milenage256.ComputeOPc(cfg, k, op)
				opc = opcArray[:]
			} else {
				// Standard Milenage
				opc, err = milenage.GenerateOPC(k, op)
				if err != nil {
					logger.UeauLog.Errorln("milenage GenerateOPC err", err)
				}
			}
		} else {
			problemDetails = &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
			}

			logger.UeauLog.Errorln("unable to derive OPC")
			return nil, problemDetails
		}
	}
	cfg := milenage256.DefaultConfig()
	// Check if using Milenage256 based on key size
	isMilenage256 := len(k) == 32
	sqnSize := 12 // Default hex length for SQN (6 bytes)
	if isMilenage256 {
		// In Milenage256, SQN is also 6 bytes, so hex length is 12.
		// If config changes, we might need to adjust, but DefaultConfig says 6 bytes.
		sqnSize = int(cfg.SqnSize) * 2
	}

	sqnStr := strictHex(authSubs.SequenceNumber, sqnSize)
	logger.UeauLog.Debugln("sqnStr", sqnStr)
	sqn, err := hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	logger.UeauLog.Debugln("sqn", sqn)
	// aqui con rand lo mismo con el tamano que con el sqn
	randSize := 16 // Default para Milenage clásico
	if isMilenage256 {
		randSize = int(cfg.RandSize)
	}
	RAND := make([]byte, randSize)
	_, err = rand.Read(RAND)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}
	//el amf dejale este valor para ambos o sea tb para milenage 256
	AMF, err := hex.DecodeString("8000")
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	// re-synchroniztion
	if authInfoRequest.ResynchronizationInfo != nil {
		Auts, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Auts)
		if deCodeErr != nil {
			problemDetails = &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
				Detail: deCodeErr.Error(),
			}

			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}

		randHex, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Rand)
		if deCodeErr != nil {
			problemDetails = &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
				Detail: deCodeErr.Error(),
			}

			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}
		// Resynchronization logic
		var SQNms, macS []byte
		if isMilenage256 {
			// Use f5* (standard) by default, set last param to false.
			// If f5** is needed, it should be configurable, but standard is f5*.
			SQNms, err = milenage256.Resynchronize(cfg, k, opc, randHex, Auts, false)
			if err != nil {
				logger.UeauLog.Errorln("Milenage256 Resynchronize err", err)
				// If MAC verification fails in Resynchronize, it returns error.
				// We treat it as MAC failure.
			}
		} else {
			SQNms, macS = aucSQN(opc, k, Auts, randHex)
		}
		// For Milenage256, err is set if MAC failed. For standard, we check manually.
		if (isMilenage256 && err == nil) || (!isMilenage256 && reflect.DeepEqual(macS, Auts[6:])) {
			_, err = rand.Read(RAND)
			if err != nil {
				problemDetails = &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: err.Error(),
				}

				logger.UeauLog.Errorln("err", err)
				return nil, problemDetails
			}

			// increment sqn authSubs.SequenceNumber
			// Se utiliza la librería math/big para manejar de forma segura la aritmética de 48 bits del SQN.
			// 1. El SQN (hex string) se convierte a un objeto big.Int.
			// 2. Se le suma un valor de incremento (ej: +33 en resincronización).
			// 3. Se aplica una operación de módulo con el valor máximo del SQN (2^48 - 1) para
			//    asegurar el comportamiento de "wrap-around" (dar la vuelta si se supera el límite).
			// 4. El nuevo valor del SQN se formatea de nuevo a un string hexadecimal de 12 caracteres.
			bigSQN := big.NewInt(0) // esta parte de aqui no la entiendo lo que hace me puedes explicar todo esto
			sqnStr = hex.EncodeToString(SQNms)
			logger.UeauLog.Infof("SQNstr %s", sqnStr)
			bigSQN.SetString(sqnStr, 16)

			bigInc := big.NewInt(ind + 1)

			bigP := big.NewInt(SqnMAx)
			bigSQN = bigInc.Add(bigSQN, bigInc)
			bigSQN = bigSQN.Mod(bigSQN, bigP)
			sqnStr = fmt.Sprintf("%x", bigSQN)
			sqnStr = strictHex(sqnStr, sqnSize)
		} else {
			logger.UeauLog.Errorln("Re-Sync MAC failed", supi)
			logger.UeauLog.Errorln("MACS", macS)
			logger.UeauLog.Errorln("Auts[int(cfg.SqnSize):]", Auts[int(cfg.SqnSize):])
			logger.UeauLog.Errorln("Sqn", SQNms)
			problemDetails = &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "modification is rejected",
			}
			return nil, problemDetails
		}
	}

	// increment sqn
	bigSQN := big.NewInt(0) // esta parte tampoco la entiendo explicamela
	sqn, err = hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	bigSQN.SetString(sqnStr, 16)

	bigInc := big.NewInt(1)
	bigSQN = bigInc.Add(bigSQN, bigInc)

	SQNheStr := fmt.Sprintf("%x", bigSQN)
	SQNheStr = strictHex(SQNheStr, sqnSize)
	patchItemArray := []models.PatchItem{
		{
			Op:    models.PatchOperation_REPLACE,
			Path:  "/sequenceNumber",
			Value: SQNheStr,
		},
	}

	var rsp *http.Response
	rsp, err = client.AuthenticationDataDocumentApi.ModifyAuthentication(
		context.Background(), supi, patchItemArray)
	if err != nil {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "modification is rejected ",
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("update sqn error", err)
		return nil, problemDetails
	}
	defer func() {
		if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("ModifyAuthentication response body cannot close: %+v", rspCloseErr)
		}
	}()
	var macA, macS, CK, IK, RES, AK, AKstar []byte
	if isMilenage256 {
		// GenerateAuthenticationVectors returns (macA, res, ck, ik, ak)
		// Note: GenerateAuthenticationVectors in milenage256.go does not return AKstar or macS (f1*).
		// Standard flow (AV generation) uses f1, f2, f3, f4, f5.

		macA, RES, CK, IK, AK = milenage256.GenerateAuthenticationVectors(cfg, k, opc, RAND, sqn, AMF)

		// AKstar is not generated by GenerateAuthenticationVectors, but it's only needed for resync (f5*).
		// Here we are generating AV, so AKstar is not strictly needed for the vector itself
		// unless we are doing EAP-AKA' or 5G AKA derivation that might depend on it?
		// Actually 5G AKA uses CK, IK.
		// EAP-AKA' uses CK', IK'.
		// Neither seems to use AKstar directly in the AV response.
	} else {
		macA, macS = make([]byte, 8), make([]byte, 8)
		CK, IK = make([]byte, 16), make([]byte, 16)
		RES = make([]byte, 8)
		AK, AKstar = make([]byte, 6), make([]byte, 6)

		// Generate macA, macS
		err = milenage.F1(opc, k, RAND, sqn, AMF, macA, macS)
		if err != nil {
			logger.UeauLog.Errorln("milenage F1 err ", err)
		}

		// Generate RES, CK, IK, AK, AKstar
		// RES == XRES (expected RES) for server
		err = milenage.F2345(opc, k, RAND, RES, CK, IK, AK, AKstar)
		if err != nil {
			logger.UeauLog.Errorln("milenage F2345 err", err)
		}
	}
	//aqui habria que valorar si llamar a milenage256.Generate5GHEAV en caso de usarse milenage256 que devuelve  autn, xResStar, kAusf o si es compatible usar el mismo codigo que esta aqui debajo solo que cambiando el size de este SQNxorAK := make([]byte, 6) por el correspondiente segun el tamano que tenga el sqn en la configuracion de milenage256.defaultconfig
	// Generate AUTN
	sqnXorAkSize := 6
	if isMilenage256 {
		sqnXorAkSize = int(cfg.SqnSize)
	}
	SQNxorAK := make([]byte, sqnXorAkSize)
	for i := 0; i < len(sqn); i++ {
		SQNxorAK[i] = sqn[i] ^ AK[i] //se supone que ak y sqn son del mismo tamano
	}
	AUTN := append(append(SQNxorAK, AMF...), macA...)
	logger.UeauLog.Infof("AUTN = %x", AUTN)

	var av models.AuthenticationVector
	if authSubs.AuthenticationMethod == models.AuthMethod__5_G_AKA {
		response.AuthType = models.AuthType__5_G_AKA

		// derive XRES*
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := RAND
		P2 := RES

		kdfValForXresStar, err := ueauth.GetKDFValue(
			key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
		if err != nil {
			logger.UeauLog.Error(err)
		}
		xresStar := kdfValForXresStar[len(kdfValForXresStar)/2:]

		// derive Kausf
		FC = ueauth.FC_FOR_KAUSF_DERIVATION
		P0 = []byte(authInfoRequest.ServingNetworkName)
		P1 = SQNxorAK
		kdfValForKausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Error(err)
		}

		// Fill in rand, xresStar, autn, kausf
		av.Rand = hex.EncodeToString(RAND)
		av.XresStar = hex.EncodeToString(xresStar)
		av.Autn = hex.EncodeToString(AUTN)
		av.Kausf = hex.EncodeToString(kdfValForKausf)
	} else { // EAP-AKA'
		response.AuthType = models.AuthType_EAP_AKA_PRIME

		// derive CK' and IK'
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := SQNxorAK
		kdfVal, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Error(err)
		}

		// For TS 35.208 test set 19 & RFC 5448 test vector 1
		// CK': 0093 962d 0dd8 4aa5 684b 045c 9edf fa04
		// IK': ccfc 230c a74f cc96 c0a5 d611 64f5 a76

		ckPrime := kdfVal[:len(kdfVal)/2]
		ikPrime := kdfVal[len(kdfVal)/2:]

		// Fill in rand, xres, autn, ckPrime, ikPrime
		av.Rand = hex.EncodeToString(RAND)
		av.Xres = hex.EncodeToString(RES)
		av.Autn = hex.EncodeToString(AUTN)
		av.CkPrime = hex.EncodeToString(ckPrime)
		av.IkPrime = hex.EncodeToString(ikPrime)
	}

	response.AuthenticationVector = &av
	response.Supi = supi
	return response, nil
}
