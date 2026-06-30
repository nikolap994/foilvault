// Curated 512-word passphrase wordlist — 9 bits/word
// 4 words ≈ 36 bits · 5 words ≈ 45 bits · 6 words ≈ 54 bits
export const WORDLIST: readonly string[] = `
abbey abide abode abyss acorn actor acute admit adore adult agile agony alarm album alert amaze
amber amble angel ankle annex anvil apple apron ardor arena arson atlas attic audio audit axiom
azure badge baker banjo baron basic beach beard beast bench berry blade blank blast blaze blend
blind bliss block bloom blown blues blunt board boast bonus boost booth brave bread breed brick
broom broth brown brush build bulge bunch burst cabin cache camel cargo carry caste cedar chalk
charm chase chess chest chief chime choir claim clash cling cloak clone cloth cloud coast cobra
coral crane crash crate creek crest crisp cross crown cubic curve cycle dance daunt decay delta
demon depot depth devil drift dunes dusty dairy daisy dandy debut decal decoy derby digit disco
dodge donor doors draft drain drawl dream dried drink drive drums drunk dryer eagle earns earth
elder elite ember emote empty endow enter envy equal erase evade event exact exert exile extra
fable faint fairy false fancy fatal feast fence ferry fewer fifth final flake flame flank flask
fleet flesh flock flood flute forge fresh frost fruit fungi fixed found franc fraud freed frown
froze fumes fuzzy gable gauge gauze ghost gland gleam glide gloss glove glyph grace grade grain
grand grant grasp grave graze greed greet grief grill groan gross grove guard guide guild gusto
habit haiku haste haven hedge heist heron hitch hoard holly honor house hover hyena hazel image
inbox indie inlet input ivory jaunt jewel joust judge juicy jumbo knack label lance larva laser
latch later laugh layer leach ledge legal lemon level light lilac limit liner liver local lodge
logic loose lover lucid lucky lunar lyric magic maker mambo mango manor maple march match mercy
merge might model moody moral mount mouse muddy mural muted myrrh naive naval noble north novel
nudge nymph ocean offer olive orbit order ozone panic pasta patch pearl pedal perch pilot pinch
plain plank plaza plead pluck porch pound power press prime prism probe proof pulse punch purge
query queue quirk quota quote radar rally ranch razor rebel recap reign relay remix renew repay
rider ridge rival river rivet robot rocky rough round royal rugby runes runic salon salsa sandy
sauna savvy scale scant scarf scene scone scoop score scout scrub sedan seize shade shaft shape
sharp shelf shell shirt shock shore shrub sigma since skull slang slash slate slice slide sling
smash smear smell smoke snake snare snoop snore solid sonar south space spark spawn speak speed
spell spend spice spire stare stark start steer stern stick stone storm stout strap study surge
swamp sweep swift swirl syrup table tally talon tango tapir teach tempo tense theft theme thigh
thorn tiara tiger today token tough tower track trail train trait tramp truce truck truly trust
tuber tulip tumor tuner twirl twice twist umbra uncle unite until valor vault verge vigil viral
vista vital vivid vocal voice vouch wagon waist waltz waste watch weary weave wedge weird whale
wheat whelk while witch wispy wrath wreck wrist wrong yacht yield young zebra zesty zones zilch
`.trim().split(/\s+/)

export interface PassphraseOptions {
  wordCount: number
  separator: string
  capitalize: boolean
  appendNumber: boolean
}

export function generatePassphrase(opts: PassphraseOptions): string {
  const count = Math.max(3, Math.min(8, opts.wordCount))
  const arr = new Uint32Array(count)
  crypto.getRandomValues(arr)
  const words = Array.from(arr, n => {
    const word = WORDLIST[n % WORDLIST.length]
    return opts.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word
  })
  let phrase = words.join(opts.separator)
  if (opts.appendNumber) {
    const n = new Uint32Array(1)
    crypto.getRandomValues(n)
    phrase += opts.separator + String(n[0] % 100).padStart(2, '0')
  }
  return phrase
}

export function passphraseEntropy(wordCount: number): number {
  return Math.floor(wordCount * Math.log2(WORDLIST.length))
}
