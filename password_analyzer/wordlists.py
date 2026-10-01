"""Word lists used by the analyzer and the generator.

COMMON_PASSWORDS: passwords that attackers try first, most common first.
WORDS: everyday words used to build passphrases and to spot dictionary words.
"""

from __future__ import annotations

COMMON_PASSWORDS = tuple(dict.fromkeys("""
123456 password 123456789 12345678 12345 qwerty 1234567 111111 123123 abc123
password1 iloveyou 1234567890 000000 1234 qwerty123 1q2w3e4r admin letmein welcome
monkey dragon football baseball master sunshine princess shadow superman michael
jessica ashley bailey charlie daniel jordan hunter buster soccer harley
batman andrew tigger robert thomas hockey ranger george computer michelle
pepper zxcvbnm asdfgh asdfghjkl qazwsx trustno1 login starwars hello freedom
whatever passw0rd killer jennifer joshua maggie summer ginger cookie matrix
secret internet flower lovely cheese banana purple orange silver yellow
google samsung pokemon naruto liverpool chelsea arsenal barcelona nicole amanda
justin taylor austin merlin mustang corvette access mercedes ferrari thunder
diamond heaven angel angels friends family love loveyou iloveu lovers
baby babygirl chocolate butterfly jesus blessed forever nothing test test123
guest root administrator changeme default system server user demo temp
pass pass123 password123 admin123 welcome1 welcome123 qwertyuiop 1qaz2wsx zaq12wsx q1w2e3r4
987654321 654321 666666 888888 7777777 121212 112233 123321 555555 999999
101010 123qwe qwe123 abcd1234 a1b2c3 aa123456 147258369 159753 1q2w3e zxcvbn
asdf asdf1234 qwer1234 monkey123 dragon123 football1 iloveyou1 princess1 sunshine1 superman1
michael1 charlie1 jordan23 password12 password2 passwort motdepasse azerty azerty123 qwertz
william matthew anthony joseph david james john richard christopher brandon
samantha elizabeth sarah hannah emily madison olivia sophia isabella emma
tiger tigers eagles lakers yankees cowboys steelers dallas boston chicago
london paris berlin madrid mexico canada america china india brazil
spring winter autumn monday friday sunday january december november october
soccer1 hockey1 baseball1 basketball tennis golf swimming running cricket rugby
guitar piano music dancer singer rockstar player gamer minecraft fortnite
pikachu mario zelda sonic spiderman ironman avengers wolverine hulk joker
secret1 secret123 private security secure mypassword mypass newpassword letmein1 opensesame
""".split()))

WORDS = tuple(dict.fromkeys("""
ant ape bat bear bee bird bison boar buck bull calf camel cat chick clam cobra cod colt cow crab
crane crow cub deer dog dove duck eagle eel elk emu fawn finch fish flea fly foal fox frog gecko
goat goose gull hare hawk hen heron horse hound ibis jay kiwi koala lamb lark lemur lion llama lynx
mole moose moth mouse mule newt otter owl ox panda parrot pig pony pug puma quail rabbit ram rat
raven robin seal shark sheep shrew skunk sloth snail snake spider squid stork swan tiger toad trout
tuna turtle viper wasp whale wolf wren yak zebra

apple apricot bacon bagel banana basil bean beef beet berry bread broth butter cake candy carrot
celery cereal cheese cherry chili cider cocoa coffee cookie corn cream crust cumin curry date dough
egg fig flour fudge garlic ginger grape gravy guava ham honey jam jelly juice kale ketchup lemon
lentil lime mango maple melon milk mint muffin nacho noodle nut oat olive onion orange pasta pea
peach pear pecan pepper pickle pie pizza plum pork potato prune pumpkin radish raisin rice salad
salmon salt sauce soup spice squash steak sugar syrup taco tea toast tofu tomato turnip vanilla
waffle walnut yogurt

acorn air ash aspen bark bay beach birch bloom bog branch breeze brook bush canyon cave cedar cliff
cloud coast coral cove creek dawn delta desert dew dune dusk earth ember fern field fjord flame
flood flower fog forest frost garden glacier glade grass grove gulf hail harbor haze hill island
ivy jungle lagoon lake lava leaf lily lotus marsh meadow mist moon moss mountain mud oak oasis
ocean orchid palm peak pebble petal pine planet pond prairie rain reef ridge river rock root rose
sand sea shade shore sky snow soil spring star stone storm stream summit sun swamp thorn thunder
tide trail tree tulip valley vine wave willow wind wood

anchor anvil arrow axe badge bag ball banner barrel basket bed bell belt bench bike blade blanket
board boat bolt book boot bottle bowl box brick bridge broom brush bucket button cabin cable camera
candle canoe cap car card carpet cart chain chair chalk chest clock cloth coat coin comb compass
cord couch crate crown cup curtain desk dial dish door drum engine fan fence flag flask flute fork
frame gate gear glass glove guitar hammer handle harp hat helmet hinge hook horn jacket jar jeans
kettle key kite knife knob ladder lamp lantern lens lever lock magnet map mask mirror mug nail
needle net oar oven paddle pan paper pedal pen pencil piano pillow pipe plate plow pocket purse
quilt radio rail razor ribbon ring rope rudder ruler saddle sail scarf screw shelf shield ship
shirt shoe shovel sink sled soap sock sofa spoon stamp stool stove string table tent thread ticket
tile tire token tool towel tower toy tractor train tray truck trunk tube vase wagon wallet watch
wheel whistle window wire wrench zipper

accept add admire agree aim allow answer arrive ask bake bend bind bite blend blink blow boil
borrow bounce bring build burn buy call carry carve catch change chase check cheer choose claim
clap clean climb close collect come cook count cover crawl cross dance dare decide deliver dig dive
draw dream dress drift drink drive drop earn eat enjoy enter explore fall feed feel fetch fill find
finish fix float fold follow forget forgive gather give glide glow grab greet grow guess guide hang
help hide hold hop hug hum hunt invite join juggle jump keep kick knit knock laugh launch lead lean
learn leave lend lift listen live look make march match measure meet melt mend mix move nod notice
obey offer open paint pass pause pick plant play point polish pour praise press print pull push
race reach read relax repair reply rest ride rinse roll row run rush save scrub search send serve
settle shake share shine shout sing sit skate skip sleep slide smile solve sort speak spell spin
stand start stay step stir stop stretch study swim swing take talk teach tell think throw tie touch
trade travel trust try turn twist visit wait walk wash weave whisper win wink wish work wrap write
yawn

able active agile alert amber ample ancient awake aware basic bold brave brief bright brisk broad
busy calm careful cheerful chief civil classic clear clever cool cosmic cozy crisp curious daily
dandy daring dear decent deep dense eager early easy elegant equal exact fair faithful famous fancy
fast fine firm fluffy fond formal frank free fresh friendly frosty funny gentle giant glad global
golden good graceful grand great handy happy hardy honest huge humble ideal jolly joyful keen kind
large lasting lively local loyal lucky lunar magic major mellow merry mighty mild modern modest
neat nimble noble novel odd patient plain pleasant polite proud pure quick quiet rapid rare ready
real regal rich robust royal rustic safe sharp shiny silent simple sleek slim smart smooth snug
social soft solar solid sound spare special steady sturdy subtle sunny super sure sweet swift tall
tender tidy tiny tough true urban useful valid vast vivid warm wide wild wise witty young zesty

azure beige black blue bronze brown copper crimson cyan ebony gold gray green indigo ivory jade
khaki lilac magenta maroon navy ochre pearl pink purple red ruby rust sage scarlet silver tan teal
violet white yellow cotton denim linen marble nylon silk steel velvet wool

alley arcade arena attic avenue bakery balcony bank barn bazaar camp canal castle cellar chapel
city clinic college corner cottage court depot diner dock dome factory farm ferry forum fountain
gallery garage hall hangar hotel house hut inn kiosk lab library lobby lodge mall manor market mill
museum office palace park patio plaza port porch ranch road school shed shop square stable stadium
station store street studio subway temple theater tunnel village villa yard zoo

actor artist author baker banker barber captain chef clerk coach dancer doctor driver editor farmer
fisher guard guest hero host judge king knight lawyer leader maker mayor miner monk nurse painter
pilot pirate poet prince queen ranger rider sailor scout singer smith tailor teacher tutor twin
uncle usher vendor waiter warden writer baby child friend girl kid lady

action advice age angle area art balance base beat birth bonus border bottom bounty brand break
budget chance chapter charm choice circle class code color comfort course craft credit culture
custom cycle data deal debate degree design detail dinner distance dozen draft echo edge effort
energy event example exit fact fame favor fiction figure flavor focus force form fortune future
game gift goal grade group habit harmony health heart height hobby honor hope humor idea image
index input item journey joy justice label layer lesson level limit line logic luck lunch margin
matter memory menu merit method middle minute moment money month motion music name nation nature
noise note number option order origin output page pair part party path pattern peace phase phrase
piece pitch place plan plot poem power price pride prize profit proof pulse quest quote range rate
reason record region report result reward rhythm risk role rule scale scene score season secret
sense shape signal size skill source space speed spirit sport stage state story style subject
summer symbol system talent task taste team theme theory thing time title topic total trend trick
truth unit value version view vision voice volume week weight winter wonder word world year zone

atom axis beam binary bit byte cell chip circuit cipher cluster comet cosmos crystal current cursor
decimal device digit disk domain electron element filter flux fossil galaxy gamma gas gene graph
gravity helix hydro ion kernel laser lattice light liquid loop matrix meteor metric micro module
motor nebula neon neuron node nova nucleus orbit oxygen ozone packet photon pixel plasma portal
prism probe proton pulsar quark quartz radar radius ratio robot rocket router sample sensor server
sigma socket sonar spark sphere switch tensor thermal titan turbine vacuum vapor vector vertex
vortex voltage widget zenith zero

one two three four five six seven eight nine ten eleven twelve twenty thirty forty fifty hundred
first second third noon night today monday friday sunday april june july august
""".split()))
