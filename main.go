package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/blowfish"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Login struct {
		Local  string `yaml:"local"`
		Remote string `yaml:"remote"`
	} `yaml:"login"`
	Game struct {
		Local  string `yaml:"local"`
		Remote string `yaml:"remote"`
	} `yaml:"game"`
	Logging struct {
		Enabled  bool   `yaml:"enabled"`
		Filename string `yaml:"filename"`
	} `yaml:"logging"`
}

var (
	configPath  = flag.String("config", "config.yaml", "Config file path")
	loginLocal  = flag.String("login-local", "", "Login proxy listen address (overrides config)")
	loginRemote = flag.String("login-remote", "", "Real login server address (overrides config)")
	gameLocal   = flag.String("game-local", "", "Game proxy listen address (overrides config)")
	gameRemote  = flag.String("game-remote", "", "Real game server address (overrides config)")
	outputPath  = flag.String("out", "", "Save decrypted packets to file (overrides config)")
)

var logFile *os.File

func main() {
	flag.Parse()

	cfg := Config{}
	cfg.Login.Local = "127.0.0.1:2106"
	cfg.Login.Remote = ""
	cfg.Game.Local = "127.0.0.1:7777"
	cfg.Game.Remote = ""

	data, err := os.ReadFile(*configPath)
	if err == nil {
		yaml.Unmarshal(data, &cfg)
	} else if *loginRemote == "" || *gameRemote == "" {
		log.Fatalf("Config file %s: %v", *configPath, err)
	}

	if *loginLocal != "" {
		cfg.Login.Local = *loginLocal
	}
	if *loginRemote != "" {
		cfg.Login.Remote = *loginRemote
	}
	if *gameLocal != "" {
		cfg.Game.Local = *gameLocal
	}
	if *gameRemote != "" {
		cfg.Game.Remote = *gameRemote
	}

	if cfg.Login.Remote == "" || cfg.Game.Remote == "" {
		log.Fatalf("Both login.remote and game.remote must be set in config or via flags")
	}

	out := *outputPath
	if out == "" && cfg.Logging.Enabled && cfg.Logging.Filename != "" {
		out = cfg.Logging.Filename
	}
	if out != "" {
		var err error
		logFile, err = os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Cannot open output file %s: %v", out, err)
		}
		defer logFile.Close()
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}

	lAddr, rAddr := cfg.Login.Local, cfg.Login.Remote
	gAddr, grAddr := cfg.Game.Local, cfg.Game.Remote

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		runLoginProxy(lAddr, rAddr)
	}()
	go func() {
		defer wg.Done()
		runGameProxy(gAddr, grAddr)
	}()

	log.Printf("L2 Proxy ready")
	log.Printf("  Login : %s → %s", lAddr, rAddr)
	log.Printf("  Game  : %s → %s", gAddr, grAddr)
	wg.Wait()
}

// ─── Login Proxy ────────────────────────────────────────────────────────────

func runLoginProxy(localAddr, remoteAddr string) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Login proxy listen on %s: %v", localAddr, err)
	}

	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Login accept: %v", err)
			continue
		}
		go handleLoginConn(client, remoteAddr)
	}
}

func handleLoginConn(client net.Conn, remoteAddr string) {
	defer client.Close()
	log.Printf("[LOGIN] Client: %s", client.RemoteAddr())

	server, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("[LOGIN] dial %s: %v", remoteAddr, err)
		return
	}
	defer server.Close()

	initData := readPacket(server)
	if initData == nil {
		return
	}
	log.Printf("[LOGIN] S→C INIT opcode=0x%02X len=%d\n%s", initData[0], len(initData), hexDump(initData))
	writePacket(client, initData)

	crypt := newBlowfish()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { relayLogin(client, server, crypt, "C→S"); wg.Done() }()
	go func() { relayLogin(server, client, crypt, "S→C"); wg.Done() }()
	wg.Wait()
}

func relayLogin(src, dst net.Conn, crypt *BlowfishCrypt, dir string) {
	for {
		data := readPacket(src)
		if data == nil {
			return
		}

		logData := make([]byte, len(data))
		copy(logData, data)
		crypt.Decrypt(logData)

		log.Printf("[LOGIN] %s op=0x%02X %-28s len=%d\n%s",
			dir, logData[0], opcodeName(dir, logData[0]), len(logData), hexDump(logData))

		if !writePacket(dst, data) {
			return
		}
	}
}

// ─── Game Proxy ─────────────────────────────────────────────────────────────

func runGameProxy(localAddr, remoteAddr string) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Game proxy listen on %s: %v", localAddr, err)
	}

	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Game accept: %v", err)
			continue
		}
		go handleGameConn(client, remoteAddr)
	}
}

func handleGameConn(client net.Conn, remoteAddr string) {
	defer client.Close()
	log.Printf("[GAME] Client: %s", client.RemoteAddr())

	server, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("[GAME] dial %s: %v", remoteAddr, err)
		return
	}
	defer server.Close()

	clientData := readPacket(client)
	if clientData == nil {
		return
	}
	log.Printf("[GAME] C→S RAW op=0x%02X len=%d\n%s", clientData[0], len(clientData), hexDump(clientData))
	writePacket(server, clientData)

	serverData := readPacket(server)
	if serverData == nil {
		return
	}
	log.Printf("[GAME] S→C RAW op=0x%02X len=%d\n%s", serverData[0], len(serverData), hexDump(serverData))
	writePacket(client, serverData)

	if len(serverData) < 6 || serverData[0] != 0x00 || serverData[1] != 0x01 {
		log.Printf("[GAME] unexpected key response, crypto logging disabled")
		return
	}
	firstKey := serverData[2:6]
	log.Printf("[GAME] XOR key: %X", firstKey)

	c2s := newGameCrypt(firstKey)
	s2c := newGameCrypt(firstKey)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { relayGame(client, server, c2s, "C→S"); wg.Done() }()
	go func() { relayGame(server, client, s2c, "S→C"); wg.Done() }()
	wg.Wait()
}

func relayGame(src, dst net.Conn, crypt *GameXorCrypt, dir string) {
	for {
		data := readPacket(src)
		if data == nil {
			return
		}

		logData := make([]byte, len(data))
		copy(logData, data)
		crypt.Decrypt(logData)

		log.Printf("[GAME] %s op=0x%02X %-28s len=%d\n%s",
			dir, logData[0], opcodeName(dir, logData[0]), len(logData), hexDump(logData))

		if !writePacket(dst, data) {
			return
		}
	}
}

// ─── Packet I/O ─────────────────────────────────────────────────────────────

func readPacket(conn net.Conn) []byte {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}
	length := binary.LittleEndian.Uint16(header)
	if length < 2 {
		return nil
	}
	data := make([]byte, length-2)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil
	}
	return data
}

func writePacket(conn net.Conn, data []byte) bool {
	pkt := make([]byte, len(data)+2)
	binary.LittleEndian.PutUint16(pkt, uint16(len(data)+2))
	copy(pkt[2:], data)
	_, err := conn.Write(pkt)
	return err == nil
}

func hexDump(data []byte) string {
	var s strings.Builder
	for i, b := range data {
		if i > 0 {
			if i%16 == 0 {
				s.WriteString("\n  ")
			} else {
				s.WriteByte(' ')
			}
		} else {
			s.WriteString("  ")
		}
		fmt.Fprintf(&s, "%02X", b)
	}
	return s.String()
}

// ─── Blowfish Crypt (Login) ─────────────────────────────────────────────────

type BlowfishCrypt struct {
	cipher *blowfish.Cipher
}

func newBlowfish() *BlowfishCrypt {
	baseKey := []byte{
		0x5b, 0x3b, 0x27, 0x2e, 0x5d, 0x39, 0x34, 0x2d,
		0x33, 0x31, 0x3d, 0x3d, 0x2d, 0x25, 0x26, 0x40,
		0x21, 0x5e, 0x2b, 0x5d,
	}
	realKey := append(baseKey, 0x00)
	c, _ := blowfish.NewCipher(realKey)
	return &BlowfishCrypt{cipher: c}
}

func (c *BlowfishCrypt) Decrypt(data []byte) {
	for i := 0; i+8 <= len(data); i += 8 {
		data[i+0], data[i+3] = data[i+3], data[i+0]
		data[i+1], data[i+2] = data[i+2], data[i+1]
		data[i+4], data[i+7] = data[i+7], data[i+4]
		data[i+5], data[i+6] = data[i+6], data[i+5]

		c.cipher.Decrypt(data[i:i+8], data[i:i+8])

		data[i+0], data[i+3] = data[i+3], data[i+0]
		data[i+1], data[i+2] = data[i+2], data[i+1]
		data[i+4], data[i+7] = data[i+7], data[i+4]
		data[i+5], data[i+6] = data[i+6], data[i+5]
	}
}

// ─── XOR Crypt (Game) ───────────────────────────────────────────────────────

type GameXorCrypt struct {
	key []byte
}

func newGameCrypt(firstKey []byte) *GameXorCrypt {
	key := make([]byte, 8)
	copy(key[0:4], firstKey)
	key[4] = 0xA1
	key[5] = 0x6C
	key[6] = 0x54
	key[7] = 0x87
	return &GameXorCrypt{key: key}
}

func (c *GameXorCrypt) Decrypt(data []byte) {
	var prev byte
	for i := 0; i < len(data); i++ {
		temp := data[i]
		data[i] = temp ^ c.key[i%8] ^ prev
		prev = temp
	}
	old := binary.LittleEndian.Uint32(c.key[0:4])
	old += uint32(len(data))
	binary.LittleEndian.PutUint32(c.key[0:4], old)
}

// ─── Opcode Names ───────────────────────────────────────────────────────────

var clientOpcodes = map[byte]string{
	0x00: "SendProtocolVersion",
	0x01: "MoveBackwardToLocation",
	0x02: "Say",
	0x03: "RequestEnterWorld",
	0x04: "Action",
	0x05: "RequestLogin",
	0x06: "RequestAttack",
	0x08: "RequestLogin2",
	0x09: "SendLogOut",
	0x0A: "RequestAttack2",
	0x0B: "RequestCharacterCreate",
	0x0C: "RequestCharacterDelete",
	0x0D: "RequestGameStart",
	0x0E: "RequestNewCharacter",
	0x0F: "RequestItemList",
	0x10: "RequestEquipItem",
	0x11: "RequestUnEquipItem",
	0x12: "RequestDropItem",
	0x14: "RequestUseItem",
	0x15: "RequestTrade",
	0x16: "RequestAddTradeItem",
	0x17: "TradeDone",
	0x1A: "RequestTeleport",
	0x1B: "SocialAction",
	0x1C: "ChangeMoveType",
	0x1D: "ChangeWaitType",
	0x1E: "RequestSellItem",
	0x1F: "RequestBuyItem",
	0x20: "RequestLinkHtml",
	0x21: "RequestBypassToServer",
	0x22: "RequestBBSWrite",
	0x23: "RequestCreatePledge",
	0x24: "RequestJoinPledge",
	0x25: "RequestAnswerJoinPledge",
	0x26: "RequestWithDrawalPledge",
	0x27: "RequestOustPledgeMember",
	0x28: "RequestDismissPledge",
	0x29: "RequestJoinParty",
	0x2A: "RequestAnswerJoinParty",
	0x2B: "RequestWithDrawalParty",
	0x2C: "RequestOustPartyMember",
	0x2D: "RequestDismissParty",
	0x2E: "RequestMagicSkillList",
	0x2F: "RequestMagicSkillUse",
	0x30: "SendAppearing",
	0x31: "SendWareHouseDepositList",
	0x32: "SendWareHouseWithdrawList",
	0x33: "RequestShortCutReg",
	0x34: "RequestShortCutUse",
	0x35: "RequestShortCutDel",
	0x36: "CanNotMoveAnymore",
	0x37: "RequestTargetCancel",
	0x38: "Say2",
	0x3C: "RequestPledgeMemberList",
	0x3E: "RequestMagicList",
	0x3F: "RequestSkillList",
	0x41: "MoveWithDelta",
	0x42: "GetOnVehicle",
	0x43: "GetOffVehicle",
	0x44: "AnswerTradeRequest",
	0x45: "RequestActionUse",
	0x46: "RequestRestart",
	0x47: "RequestSiegeInfo",
	0x48: "ValidateLocation",
	0x49: "RequestSEKCustom",
	0x4A: "StartRotating",
	0x4B: "FinishRotating",
	0x4D: "RequestStartPledgeWar",
	0x4E: "RequestReplyStartPledgeWar",
	0x4F: "RequestStopPledgeWar",
	0x50: "RequestReplyStopPledgeWar",
	0x51: "RequestSurrenderPledgeWar",
	0x52: "RequestReplySurrenderPledgeWar",
	0x53: "RequestSetPledgeCrest",
	0x55: "RequestGiveNickName",
	0x57: "RequestShowboard",
	0x58: "RequestEnchantItem",
	0x59: "RequestDestroyItem",
	0x5B: "SendBypassBuildCmd",
	0x5C: "MoveToLocationInVehicle",
	0x5D: "CanNotMoveAnymore(Vehicle)",
	0x5E: "RequestFriendInvite",
	0x5F: "RequestFriendAddReply",
	0x60: "RequestFriendInfoList",
	0x61: "RequestFriendDel",
	0x62: "RequestCharacterRestore",
	0x63: "RequestQuestList",
	0x64: "RequestDestroyQuest",
	0x66: "RequestPledgeInfo",
	0x67: "RequestPledgeExtendedInfo",
	0x68: "RequestPledgeCrest",
	0x69: "RequestSurrenderPersonally",
	0x6A: "RequestRide",
	0x6B: "RequestAcquireSkillInfo",
	0x6C: "RequestAcquireSkill",
	0x6D: "RequestRestartPoint",
	0x6E: "RequestGMCommand",
	0x6F: "RequestPartyMatchConfig",
	0x70: "RequestPartyMatchList",
	0x71: "RequestPartyMatchDetail",
	0x72: "RequestCrystallizeItem",
	0x73: "RequestPrivateStoreSellManageList",
	0x74: "SetPrivateStoreSellList",
	0x75: "RequestPrivateStoreSellManageCancel",
	0x76: "RequestPrivateStoreSellQuit",
	0x77: "SetPrivateStoreSellMsg",
	0x79: "SendPrivateStoreBuyList",
	0x7A: "RequestReviveReply",
	0x7B: "RequestTutorialLinkHtml",
	0x7C: "RequestTutorialPassCmdToServer",
	0x7D: "RequestTutorialQuestionMarkPressed",
	0x7E: "RequestTutorialClientEvent",
	0x7F: "RequestPetition",
	0x80: "RequestPetitionCancel",
	0x81: "RequestGMList",
	0x82: "RequestJoinAlly",
	0x83: "RequestAnswerJoinAlly",
	0x84: "RequestWithdrawAlly",
	0x85: "RequestOustAlly",
	0x86: "RequestDismissAlly",
	0x87: "RequestSetAllyCrest",
	0x88: "RequestAllyCrest",
	0x89: "RequestChangePetName",
	0x8A: "RequestPetUseItem",
	0x8B: "RequestGiveItemToPet",
	0x8C: "RequestGetItemFromPet",
	0x8E: "RequestAllyInfo",
	0x8F: "RequestPetGetItem",
	0x90: "RequestPrivateStoreBuyManageList",
	0x91: "SetPrivateStoreBuyList",
	0x93: "RequestPrivateStoreBuyManageQuit",
	0x94: "SetPrivateStoreBuyMsg",
	0x96: "SendPrivateStoreSellList",
	0x97: "SendTimeCheck",
	0x98: "RequestStartAllianceWar",
	0x99: "ReplyStartAllianceWar",
	0x9A: "RequestStopAllianceWar",
	0x9B: "ReplyStopAllianceWar",
	0x9C: "RequestSurrenderAllianceWar",
	0x9D: "RequestSkillCoolTime",
	0x9E: "RequestPackageSendableItemList",
	0x9F: "RequestPackageSend",
	0xA0: "RequestBlock",
	0xA1: "RequestCastleSiegeInfo",
	0xA2: "RequestCastleSiegeAttackerList",
	0xA3: "RequestCastleSiegeDefenderList",
	0xA4: "RequestJoinCastleSiege",
	0xA5: "RequestConfirmCastleSiegeWaitingList",
	0xA6: "RequestSetCastleSiegeTime",
	0xA7: "RequestMultiSellChoose",
	0xA8: "NetPing",
	0xA9: "RequestRemainTime",
}

var serverOpcodes = map[byte]string{
	0x00: "VersionCheck",
	0x01: "MoveToLocation",
	0x02: "NpcSay",
	0x03: "CharInfo",
	0x04: "UserInfo",
	0x05: "Dummy_05",
	0x06: "Attack",
	0x08: "Attacked",
	0x0A: "AttackCanceled",
	0x0B: "Die",
	0x0C: "Revive",
	0x0D: "AttackOutofRange",
	0x0E: "AttackinCoolTime",
	0x0F: "AttackDeadTarget",
	0x10: "LeaveWorld",
	0x11: "AuthLoginSuccess",
	0x12: "AuthLoginFail",
	0x13: "Dummy_13",
	0x14: "Dummy_14",
	0x15: "SpawnItem",
	0x16: "DropItem",
	0x17: "GetItem",
	0x18: "EquipItem",
	0x19: "UnequipItem",
	0x1A: "StatusUpdate",
	0x1B: "NpcHtmlMessage",
	0x1C: "SellList",
	0x1D: "BuyList",
	0x1E: "DeleteObject",
	0x1F: "CharacterSelectionInfo",
	0x20: "LoginFail",
	0x21: "CharacterSelected",
	0x22: "NpcInfo",
	0x23: "NewCharacterSuccess",
	0x24: "NewCharacterFail",
	0x25: "CharacterCreateSuccess",
	0x26: "CharacterCreateFail",
	0x27: "ItemList",
	0x28: "SunRise",
	0x29: "SunSet",
	0x2A: "EquipItemSuccess",
	0x2B: "EquipItemFail",
	0x2C: "UnEquipItemSuccess",
	0x2D: "UnEquipItemFail",
	0x2E: "TradeStart",
	0x2F: "TradeStartOk",
	0x30: "TradeOwnAdd",
	0x31: "TradeOtherAdd",
	0x32: "TradeDone",
	0x33: "CharacterDeleteSuccess",
	0x34: "CharacterDeleteFail",
	0x35: "ActionFail",
	0x36: "ServerClose",
	0x37: "InventoryUpdate",
	0x38: "TeleportToLocation",
	0x39: "TargetSelected",
	0x3A: "TargetUnselected",
	0x3B: "AutoAttackStart",
	0x3C: "AutoAttackStop",
	0x3D: "SocialAction",
	0x3E: "ChangeMoveType",
	0x3F: "ChangeWaitType",
	0x40: "NetworkFail",
	0x41: "Dummy_41",
	0x42: "Dummy_42",
	0x43: "CreatePledge",
	0x44: "AskJoinPledge",
	0x45: "JoinPledge",
	0x46: "WithdrawalPledge",
	0x47: "OustPledgeMember",
	0x48: "SetOustPledgeMember",
	0x49: "DismissPledge",
	0x4A: "SetDismissPledge",
	0x4B: "AskJoinParty",
	0x4C: "JoinParty",
	0x4D: "WithdrawalParty",
	0x4E: "OustPartyMember",
	0x4F: "SetOustPartyMember",
	0x50: "DismissParty",
	0x51: "SetDismissParty",
	0x52: "MagicAndSkillList",
	0x53: "WareHouseDepositList",
	0x54: "WareHouseWithdrawList",
	0x55: "WareHouseDone",
	0x56: "ShortCutRegister",
	0x57: "ShortCutInit",
	0x58: "ShortCutDelete",
	0x59: "StopMove",
	0x5A: "MagicSkillUse",
	0x5B: "MagicSkillCanceled",
	0x5C: "Dummy_5C",
	0x5D: "Say2",
	0x5E: "EquipUpdate",
	0x5F: "StopMoveWithLocation",
	0x60: "DoorInfo",
	0x61: "DoorStatusUpdate",
	0x62: "Dummy_62",
	0x63: "PartySmallWindowAll",
	0x64: "PartySmallWindowAdd",
	0x65: "PartySmallWindowDeleteAll",
	0x66: "PartySmallWindowDelete",
	0x67: "PartySmallWindowUpdate",
	0x68: "PledgeShowMemberListAll",
	0x69: "PledgeShowMemberListUpdate",
	0x6A: "PledgeShowMemberListAdd",
	0x6B: "PledgeShowMemberListDelete",
	0x6C: "MagicList",
	0x6D: "SkillList",
	0x6E: "VehicleInfo",
	0x6F: "VehicleDeparture",
	0x70: "VehicleCheckLocation",
	0x71: "GetOnVehicle",
	0x72: "GetOffVehicle",
	0x73: "TradeRequest",
	0x74: "RestartResponse",
	0x75: "MoveToPawn",
	0x76: "ValidateLocation",
	0x77: "StartRotating",
	0x78: "FinishRotating",
	0x7A: "SystemMessage",
	0x7B: "Dummy_7B",
	0x7C: "Dummy_7C",
	0x7D: "StartPledgeWar",
	0x7E: "ReplyStartPledgeWar",
	0x7F: "StopPledgeWar",
	0x80: "ReplyStopPledgeWar",
	0x81: "SurrenderPledgeWar",
	0x82: "ReplySurrenderPledgeWar",
	0x83: "SetPledgeCrest",
	0x84: "PledgeCrest",
	0x85: "SetupGauge",
	0x86: "ShowBoard",
	0x87: "ChooseInventoryItem",
	0x88: "Dummy_88",
	0x89: "MoveToLocationInVehicle",
	0x8A: "StopMoveInVehicle",
	0x8B: "ValidateLocationInVehicle",
	0x8C: "TradeUpdate",
	0x8D: "TradePressOwnOk",
	0x8E: "MagicSkillLaunched",
	0x8F: "FriendAddRequestResult",
	0x90: "FriendAdd",
	0x91: "FriendRemove",
	0x92: "FriendList",
	0x93: "FriendStatus",
	0x94: "TradePressOtherOk",
	0x95: "FriendAddRequest",
	0x96: "LogOutOk",
	0x97: "AbnormalStatusUpdate",
	0x98: "QuestList",
	0x99: "EnchantResult",
	0x9A: "AuthServerList",
	0x9B: "PledgeShowMemberListDeleteAll",
	0x9C: "PledgeInfo",
	0x9D: "PledgeExtendedInfo",
	0x9E: "SurrenderPersonally",
	0x9F: "Ride",
	0xA0: "GiveNickNameDone",
	0xA1: "PledgeShowInfoUpdate",
	0xA2: "ClientAction",
	0xA3: "AcquireSkillList",
	0xA4: "AcquireSkillInfo",
	0xA5: "ServerObjectInfo",
	0xA6: "GMHide",
	0xA7: "AcquireSkillDone",
	0xA8: "GMViewCharacterInfo",
	0xA9: "GMViewPledgeInfo",
	0xAA: "GMViewSkillInfo",
	0xAB: "GMViewMagicInfo",
	0xAC: "GMViewQuestInfo",
	0xAD: "GMViewItemList",
	0xAE: "GMViewWarehouseWithdrawList",
	0xAF: "PartyMatchList",
	0xB0: "PartyMatchDetail",
	0xB1: "PlaySound",
	0xB2: "StaticObject",
	0xB3: "PrivateStoreSellManageList",
	0xB4: "PrivateStoreSellList",
	0xB5: "PrivateStoreSellMsg",
	0xB6: "ShowMinimap",
	0xB7: "ReviveRequest",
	0xB8: "AbnormalVisualEffect",
	0xB9: "TutorialShowHtml",
	0xBA: "ShowTutorialMark",
	0xBB: "TutorialEnableClientEvent",
	0xBC: "TutorialCloseHtml",
	0xBD: "ShowRadar",
	0xBE: "DeleteRadar",
	0xBF: "MyTargetSelected",
	0xC0: "PartyMemberPosition",
	0xC1: "AskJoinAlliance",
	0xC2: "JoinAlliance",
	0xC3: "WithdrawAlliance",
	0xC4: "OustAllianceMemberPledge",
	0xC5: "DismissAlliance",
	0xC6: "SetAllianceCrest",
	0xC7: "AllianceCrest",
	0xC8: "ServerCloseSocket",
	0xC9: "PetStatusShow",
	0xCA: "PetInfo",
	0xCB: "PetItemList",
	0xCC: "PetInventoryUpdate",
	0xCD: "AllianceInfo",
	0xCE: "PetStatusUpdate",
	0xCF: "PetDelete",
	0xD0: "PrivateStoreBuyManageList",
	0xD1: "PrivateStoreBuyList",
	0xD2: "PrivateStoreBuyMsg",
	0xD3: "VehicleStart",
	0xD4: "RequestTimeCheck",
	0xD5: "StartAllianceWar",
	0xD6: "ReplyStartAllianceWar",
	0xD7: "StopAllianceWar",
	0xD8: "ReplyStopAllianceWar",
	0xD9: "SurrenderAllianceWar",
	0xDA: "SkillCoolTime",
	0xDB: "PackageToList",
	0xDC: "PackageSendableList",
	0xDD: "EarthQuake",
	0xDE: "FlyToLocation",
	0xDF: "BlockList",
	0xE0: "SpecialCamera",
	0xE1: "NormalCamera",
	0xE2: "CastleSiegeInfo",
	0xE3: "CastleSiegeAttackerList",
	0xE4: "CastleSiegeDefenderList",
	0xE5: "NickNameChanged",
	0xE6: "PledgeStatusChanged",
	0xE7: "RelationChanged",
	0xE8: "EventTrigger",
	0xE9: "MultiSellList",
	0xEA: "SetSummonRemainTime",
	0xEB: "SkillRemainSec",
	0xEC: "NetPing",
	0xED: "Dummy_ED",
}

func opcodeName(dir string, opcode byte) string {
	var m map[byte]string
	if dir == "C→S" {
		m = clientOpcodes
	} else {
		m = serverOpcodes
	}
	if name, ok := m[opcode]; ok {
		return name
	}
	return "??"
}
