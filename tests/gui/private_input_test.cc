#include "private_input.h"
#include "shell.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>

using namespace quietproof::gui;
namespace {
int checks = 0;
void Check(bool value, const char* label) {
  ++checks;
  if (!value) throw std::runtime_error(label);
}
bool Zero(const void* pointer, size_t size) {
  const auto* p = static_cast<const unsigned char*>(pointer);
  return std::all_of(p,p+size,[](auto byte) { return byte == 0; });
}
SDL_Event Key(SDL_Keycode key, SDL_Keymod modifier = KMOD_NONE) {
  SDL_Event e{}; e.type = SDL_KEYDOWN; e.key.keysym.sym = key; e.key.keysym.mod = modifier; return e;
}
std::shared_ptr<const VerifiedProof> PublicFixture() {
  proofs::QuietProofStatementV1 s; s.verifier="state.example"; s.purpose="proof-of-control";
  s.nonce[0]=1; s.bip322_message_hash[0]=2; s.not_before=100; s.expires_at=200;
  proofs::QuietProofClaimV1 c; c.txid[0]=1; c.amount_sats=1; c.program[0]=1; s.claims.push_back(c);
  std::vector<uint8_t> bytes; Check(proofs::EncodeQuietProofStatement(s,&bytes),"state fixture canonical request");
  proofs::QuietProofEnvelopeV1 e; e.statement=s; e.envelope_version=2; e.proof_created_at=150;
  e.proof.bytes={1}; e.proof.circuit_digest[0]=1;
  auto value=ProofValidation::Run(std::make_shared<const LoadedRequest>(LoadedRequest{{},bytes,s}),e,[]{return false;},[](const auto&){return true;});
  Check(bool(value.proof),"state fixture sealed through binding/encoding checks"); return value.proof;
}
}
int main() {
  try {
    static_assert(!std::is_copy_constructible_v<PrivateInput> && !std::is_move_constructible_v<PrivateInput>);
    Check(SDL_Init(SDL_INIT_VIDEO|SDL_INIT_EVENTS) == 0,"SDL input initialization");
    PrivateInput input;
    std::array<char,PrivateInput::kCapacity> synthetic{};
    for (size_t i=0;i<synthetic.size();++i) synthetic[i]=static_cast<char>(65+i%20);
    Check(input.Append({synthetic.data(),synthetic.size()}) && input.Size() == PrivateInput::kCapacity,"bounded capacity accepted");
    Check(!input.Append({synthetic.data(),1}) && input.Size() == PrivateInput::kCapacity,"overflow refused atomically");
    input.Clear();
    Check(input.Size() == 0 && Zero(&input,PrivateInput::kCapacity),"clear overwrites entire owned capacity");
    const char unicode[] = {char(0xc3),char(0xa9),char(0xf0),char(0x9f),char(0x94),char(0x92)};
    Check(input.Append({unicode,sizeof(unicode)}),"complete Unicode commits accepted");
    input.Backspace(); Check(input.Size() == 2 && Zero(reinterpret_cast<const char*>(&input)+2,4),"Unicode backspace erases complete character");
    input.Backspace(); Check(input.Size() == 0 && Zero(&input,PrivateInput::kCapacity),"last character erased");
    for (const auto invalid : {std::string_view("\0",1),std::string_view("\n",1),std::string_view("\xc0\x80",2),
         std::string_view("\xed\xa0\x80",3),std::string_view("\xf4\x90\x80\x80",4),std::string_view("\xe2",1)})
      Check(!input.Append(invalid) && input.Size() == 0,"invalid or control commit rejected");
    Check(SDL_SetClipboardText("public clipboard sentinel") == 0,"public clipboard sentinel installed");
    Check(input.Append({synthetic.data(),12}),"synthetic input appended");
    for (const auto key : {SDLK_c,SDLK_x,SDLK_v,SDLK_z,SDLK_y,SDLK_INSERT}) {
      auto event = Key(key,KMOD_CTRL);
      Check(HandlePrivateEvent(input,event,true) == PrivateAction::None && input.Size() == 12,"clipboard/history shortcut refused");
    }
    for (const auto modifier : {KMOD_GUI,KMOD_CTRL}) {
      auto event = Key(SDLK_c,modifier);
      HandlePrivateEvent(input,event,true);
    }
    auto insert = Key(SDLK_INSERT,KMOD_SHIFT); HandlePrivateEvent(input,insert,true);
    std::unique_ptr<char,decltype(&SDL_free)> clipboard(SDL_GetClipboardText(),SDL_free);
    Check(clipboard && std::string_view(clipboard.get()) == "public clipboard sentinel" && input.Size() == 12,"clipboard unchanged and paste refused");
    auto event = Key(SDLK_DELETE); HandlePrivateEvent(input,event,true);
    Check(input.Size() == 0 && Zero(&input,PrivateInput::kCapacity),"Delete erases without undo");
    event = {}; event.type=SDL_TEXTINPUT;
    std::copy_n(synthetic.data(),12,event.text.text);
    HandlePrivateEvent(input,event,true);
    Check(input.Size() == 12 && Zero(event.text.text,sizeof(event.text.text)),"SDL text consumed and erased");
    event={}; event.type=SDL_TEXTINPUT; std::copy_n(synthetic.data(),12,event.text.text);
    HandlePrivateEvent(input,event,false);
    Check(input.Size() == 12 && Zero(event.text.text,sizeof(event.text.text)),"inactive secret field discards text");
    event={}; event.type=SDL_TEXTEDITING; std::copy_n(synthetic.data(),12,event.edit.text);
    HandlePrivateEvent(input,event,true);
    Check(Zero(event.edit.text,sizeof(event.edit.text)) && input.Size() == 12,"composition not rendered or retained");
    event={}; event.type=SDL_TEXTEDITING_EXT; event.editExt.text=static_cast<char*>(SDL_malloc(13));
    std::copy_n(synthetic.data(),12,event.editExt.text); event.editExt.text[12]=0;
    ErasePrivateEvent(event); Check(!event.editExt.text,"extended composition erased and released");
    event={}; event.type=SDL_TEXTINPUT; std::copy_n(synthetic.data(),12,event.text.text);
    Check(SDL_PushEvent(&event) == 1,"queued text precondition"); ErasePrivateEvent(event);
    DrainPrivateTextEvents(); Check(SDL_PeepEvents(&event,1,SDL_PEEKEVENT,SDL_TEXTINPUT,SDL_TEXTINPUT)==0,"queued text drained");
    event=Key(SDLK_ESCAPE); Check(HandlePrivateEvent(input,event,true)==PrivateAction::Cancel,"explicit cancel action");
    input.Clear(); Check(Zero(&input,PrivateInput::kCapacity),"cancel owner erasure");
    alignas(PrivateInput) std::array<unsigned char,sizeof(PrivateInput)> storage{};
    auto* owned = new (storage.data()) PrivateInput;
    owned->Append({synthetic.data(),synthetic.size()}); owned->~PrivateInput();
    Check(Zero(storage.data(),PrivateInput::kCapacity),"destruction overwrites full input capacity");
    for (const bool context_change : {false,true}) {
      ShellState state;
      state.wallet_status = "Request-matching key checked and erased.";
      const std::string warning = "Wallet previous-identity: relock failed; check its timed fallback.";
      state.wallet_warning = warning;
      state.wallet_prompt = true;
      state.completed_proof = PublicFixture();
      state.wallet_input->Append({synthetic.data(),12});
      if (context_change) state.InvalidateNodeProbe();
      else state.CancelWalletInput(); // Also used before explicit wallet selection changes.
      Check(state.wallet_status.empty(),"old wallet success cleared on session/context invalidation");
      Check(!state.completed_proof,"completed proof cleared on session/context invalidation");
      Check(state.wallet_warning == warning,"cleanup warning keeps captured wallet identity");
      Check(!state.wallet_prompt && !state.wallet_job && state.wallet_input->Size()==0 && state.cancel_wallet,
            "invalidated wallet input/job cleared and cancellation requested");
    }
    {
      ShellState state; state.wallet_busy = true;
      Check(state.WalletPrivatePhase(),"input guarded during wallet preflight");
      state.proof_progress = ProofEvent{1,ProofStage::Unlock};
      Check(state.WalletPrivatePhase(),"input guarded while password may be in use");
      state.proof_progress = ProofEvent{1,ProofStage::Prove};
      Check(!state.WalletPrivatePhase(),"ordinary keyboard editing resumes after consumed-password boundary");
      state.InvalidateNodeProbe();
      Check(state.wallet_cancel_pending && !state.wallet_job && !state.completed_proof,"edits cancel old proof without retaining its output");
    }
    ErasePrivateMemory(synthetic.data(),synthetic.size());
    SDL_Quit();
    std::cout << "Private input: " << checks << " checks passed; held=0 in-flight=0\n";
    return 0;
  } catch (const std::exception& error) { SDL_Quit(); std::cerr << error.what() << '\n'; return 1; }
}
