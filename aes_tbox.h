#ifndef __AES_TBOX_R__
#define __AES_TBOX_R__

#include "types.h"

const uint Te0_r[] = {
    0xa56363c6U, 0x847c7cf8U, 0x997777eeU, 0x8d7b7bf6U, 
    0x0df2f2ffU, 0xbd6b6bd6U, 0xb16f6fdeU, 0x54c5c591U, 
    0x50303060U, 0x03010102U, 0xa96767ceU, 0x7d2b2b56U, 
    0x19fefee7U, 0x62d7d7b5U, 0xe6abab4dU, 0x9a7676ecU, 
    0x45caca8fU, 0x9d82821fU, 0x40c9c989U, 0x877d7dfaU, 
    0x15fafaefU, 0xeb5959b2U, 0xc947478eU, 0x0bf0f0fbU, 
    0xecadad41U, 0x67d4d4b3U, 0xfda2a25fU, 0xeaafaf45U, 
    0xbf9c9c23U, 0xf7a4a453U, 0x967272e4U, 0x5bc0c09bU, 
    0xc2b7b775U, 0x1cfdfde1U, 0xae93933dU, 0x6a26264cU, 
    0x5a36366cU, 0x413f3f7eU, 0x02f7f7f5U, 0x4fcccc83U, 
    0x5c343468U, 0xf4a5a551U, 0x34e5e5d1U, 0x08f1f1f9U, 
    0x937171e2U, 0x73d8d8abU, 0x53313162U, 0x3f15152aU, 
    0x0c040408U, 0x52c7c795U, 0x65232346U, 0x5ec3c39dU, 
    0x28181830U, 0xa1969637U, 0x0f05050aU, 0xb59a9a2fU, 
    0x0907070eU, 0x36121224U, 0x9b80801bU, 0x3de2e2dfU, 
    0x26ebebcdU, 0x6927274eU, 0xcdb2b27fU, 0x9f7575eaU, 
    0x1b090912U, 0x9e83831dU, 0x742c2c58U, 0x2e1a1a34U, 
    0x2d1b1b36U, 0xb26e6edcU, 0xee5a5ab4U, 0xfba0a05bU, 
    0xf65252a4U, 0x4d3b3b76U, 0x61d6d6b7U, 0xceb3b37dU, 
    0x7b292952U, 0x3ee3e3ddU, 0x712f2f5eU, 0x97848413U, 
    0xf55353a6U, 0x68d1d1b9U, 0x00000000U, 0x2cededc1U, 
    0x60202040U, 0x1ffcfce3U, 0xc8b1b179U, 0xed5b5bb6U, 
    0xbe6a6ad4U, 0x46cbcb8dU, 0xd9bebe67U, 0x4b393972U, 
    0xde4a4a94U, 0xd44c4c98U, 0xe85858b0U, 0x4acfcf85U, 
    0x6bd0d0bbU, 0x2aefefc5U, 0xe5aaaa4fU, 0x16fbfbedU, 
    0xc5434386U, 0xd74d4d9aU, 0x55333366U, 0x94858511U, 
    0xcf45458aU, 0x10f9f9e9U, 0x06020204U, 0x817f7ffeU, 
    0xf05050a0U, 0x443c3c78U, 0xba9f9f25U, 0xe3a8a84bU, 
    0xf35151a2U, 0xfea3a35dU, 0xc0404080U, 0x8a8f8f05U, 
    0xad92923fU, 0xbc9d9d21U, 0x48383870U, 0x04f5f5f1U, 
    0xdfbcbc63U, 0xc1b6b677U, 0x75dadaafU, 0x63212142U, 
    0x30101020U, 0x1affffe5U, 0x0ef3f3fdU, 0x6dd2d2bfU, 
    0x4ccdcd81U, 0x140c0c18U, 0x35131326U, 0x2fececc3U, 
    0xe15f5fbeU, 0xa2979735U, 0xcc444488U, 0x3917172eU, 
    0x57c4c493U, 0xf2a7a755U, 0x827e7efcU, 0x473d3d7aU, 
    0xac6464c8U, 0xe75d5dbaU, 0x2b191932U, 0x957373e6U, 
    0xa06060c0U, 0x98818119U, 0xd14f4f9eU, 0x7fdcdca3U, 
    0x66222244U, 0x7e2a2a54U, 0xab90903bU, 0x8388880bU, 
    0xca46468cU, 0x29eeeec7U, 0xd3b8b86bU, 0x3c141428U, 
    0x79dedea7U, 0xe25e5ebcU, 0x1d0b0b16U, 0x76dbdbadU, 
    0x3be0e0dbU, 0x56323264U, 0x4e3a3a74U, 0x1e0a0a14U, 
    0xdb494992U, 0x0a06060cU, 0x6c242448U, 0xe45c5cb8U, 
    0x5dc2c29fU, 0x6ed3d3bdU, 0xefacac43U, 0xa66262c4U, 
    0xa8919139U, 0xa4959531U, 0x37e4e4d3U, 0x8b7979f2U, 
    0x32e7e7d5U, 0x43c8c88bU, 0x5937376eU, 0xb76d6ddaU, 
    0x8c8d8d01U, 0x64d5d5b1U, 0xd24e4e9cU, 0xe0a9a949U, 
    0xb46c6cd8U, 0xfa5656acU, 0x07f4f4f3U, 0x25eaeacfU, 
    0xaf6565caU, 0x8e7a7af4U, 0xe9aeae47U, 0x18080810U, 
    0xd5baba6fU, 0x887878f0U, 0x6f25254aU, 0x722e2e5cU, 
    0x241c1c38U, 0xf1a6a657U, 0xc7b4b473U, 0x51c6c697U, 
    0x23e8e8cbU, 0x7cdddda1U, 0x9c7474e8U, 0x211f1f3eU, 
    0xdd4b4b96U, 0xdcbdbd61U, 0x868b8b0dU, 0x858a8a0fU, 
    0x907070e0U, 0x423e3e7cU, 0xc4b5b571U, 0xaa6666ccU, 
    0xd8484890U, 0x05030306U, 0x01f6f6f7U, 0x120e0e1cU, 
    0xa36161c2U, 0x5f35356aU, 0xf95757aeU, 0xd0b9b969U, 
    0x91868617U, 0x58c1c199U, 0x271d1d3aU, 0xb99e9e27U, 
    0x38e1e1d9U, 0x13f8f8ebU, 0xb398982bU, 0x33111122U, 
    0xbb6969d2U, 0x70d9d9a9U, 0x898e8e07U, 0xa7949433U, 
    0xb69b9b2dU, 0x221e1e3cU, 0x92878715U, 0x20e9e9c9U, 
    0x49cece87U, 0xff5555aaU, 0x78282850U, 0x7adfdfa5U, 
    0x8f8c8c03U, 0xf8a1a159U, 0x80898909U, 0x170d0d1aU, 
    0xdabfbf65U, 0x31e6e6d7U, 0xc6424284U, 0xb86868d0U, 
    0xc3414182U, 0xb0999929U, 0x772d2d5aU, 0x110f0f1eU, 
    0xcbb0b07bU, 0xfc5454a8U, 0xd6bbbb6dU, 0x3a16162cU, 
};

const uint Te1_r[] = {
    0x6363c6a5U, 0x7c7cf884U, 0x7777ee99U, 0x7b7bf68dU, 
    0xf2f2ff0dU, 0x6b6bd6bdU, 0x6f6fdeb1U, 0xc5c59154U, 
    0x30306050U, 0x01010203U, 0x6767cea9U, 0x2b2b567dU, 
    0xfefee719U, 0xd7d7b562U, 0xabab4de6U, 0x7676ec9aU, 
    0xcaca8f45U, 0x82821f9dU, 0xc9c98940U, 0x7d7dfa87U, 
    0xfafaef15U, 0x5959b2ebU, 0x47478ec9U, 0xf0f0fb0bU, 
    0xadad41ecU, 0xd4d4b367U, 0xa2a25ffdU, 0xafaf45eaU, 
    0x9c9c23bfU, 0xa4a453f7U, 0x7272e496U, 0xc0c09b5bU, 
    0xb7b775c2U, 0xfdfde11cU, 0x93933daeU, 0x26264c6aU, 
    0x36366c5aU, 0x3f3f7e41U, 0xf7f7f502U, 0xcccc834fU, 
    0x3434685cU, 0xa5a551f4U, 0xe5e5d134U, 0xf1f1f908U, 
    0x7171e293U, 0xd8d8ab73U, 0x31316253U, 0x15152a3fU, 
    0x0404080cU, 0xc7c79552U, 0x23234665U, 0xc3c39d5eU, 
    0x18183028U, 0x969637a1U, 0x05050a0fU, 0x9a9a2fb5U, 
    0x07070e09U, 0x12122436U, 0x80801b9bU, 0xe2e2df3dU, 
    0xebebcd26U, 0x27274e69U, 0xb2b27fcdU, 0x7575ea9fU, 
    0x0909121bU, 0x83831d9eU, 0x2c2c5874U, 0x1a1a342eU, 
    0x1b1b362dU, 0x6e6edcb2U, 0x5a5ab4eeU, 0xa0a05bfbU, 
    0x5252a4f6U, 0x3b3b764dU, 0xd6d6b761U, 0xb3b37dceU, 
    0x2929527bU, 0xe3e3dd3eU, 0x2f2f5e71U, 0x84841397U, 
    0x5353a6f5U, 0xd1d1b968U, 0x00000000U, 0xededc12cU, 
    0x20204060U, 0xfcfce31fU, 0xb1b179c8U, 0x5b5bb6edU, 
    0x6a6ad4beU, 0xcbcb8d46U, 0xbebe67d9U, 0x3939724bU, 
    0x4a4a94deU, 0x4c4c98d4U, 0x5858b0e8U, 0xcfcf854aU, 
    0xd0d0bb6bU, 0xefefc52aU, 0xaaaa4fe5U, 0xfbfbed16U, 
    0x434386c5U, 0x4d4d9ad7U, 0x33336655U, 0x85851194U, 
    0x45458acfU, 0xf9f9e910U, 0x02020406U, 0x7f7ffe81U, 
    0x5050a0f0U, 0x3c3c7844U, 0x9f9f25baU, 0xa8a84be3U, 
    0x5151a2f3U, 0xa3a35dfeU, 0x404080c0U, 0x8f8f058aU, 
    0x92923fadU, 0x9d9d21bcU, 0x38387048U, 0xf5f5f104U, 
    0xbcbc63dfU, 0xb6b677c1U, 0xdadaaf75U, 0x21214263U, 
    0x10102030U, 0xffffe51aU, 0xf3f3fd0eU, 0xd2d2bf6dU, 
    0xcdcd814cU, 0x0c0c1814U, 0x13132635U, 0xececc32fU, 
    0x5f5fbee1U, 0x979735a2U, 0x444488ccU, 0x17172e39U, 
    0xc4c49357U, 0xa7a755f2U, 0x7e7efc82U, 0x3d3d7a47U, 
    0x6464c8acU, 0x5d5dbae7U, 0x1919322bU, 0x7373e695U, 
    0x6060c0a0U, 0x81811998U, 0x4f4f9ed1U, 0xdcdca37fU, 
    0x22224466U, 0x2a2a547eU, 0x90903babU, 0x88880b83U, 
    0x46468ccaU, 0xeeeec729U, 0xb8b86bd3U, 0x1414283cU, 
    0xdedea779U, 0x5e5ebce2U, 0x0b0b161dU, 0xdbdbad76U, 
    0xe0e0db3bU, 0x32326456U, 0x3a3a744eU, 0x0a0a141eU, 
    0x494992dbU, 0x06060c0aU, 0x2424486cU, 0x5c5cb8e4U, 
    0xc2c29f5dU, 0xd3d3bd6eU, 0xacac43efU, 0x6262c4a6U, 
    0x919139a8U, 0x959531a4U, 0xe4e4d337U, 0x7979f28bU, 
    0xe7e7d532U, 0xc8c88b43U, 0x37376e59U, 0x6d6ddab7U, 
    0x8d8d018cU, 0xd5d5b164U, 0x4e4e9cd2U, 0xa9a949e0U, 
    0x6c6cd8b4U, 0x5656acfaU, 0xf4f4f307U, 0xeaeacf25U, 
    0x6565caafU, 0x7a7af48eU, 0xaeae47e9U, 0x08081018U, 
    0xbaba6fd5U, 0x7878f088U, 0x25254a6fU, 0x2e2e5c72U, 
    0x1c1c3824U, 0xa6a657f1U, 0xb4b473c7U, 0xc6c69751U, 
    0xe8e8cb23U, 0xdddda17cU, 0x7474e89cU, 0x1f1f3e21U, 
    0x4b4b96ddU, 0xbdbd61dcU, 0x8b8b0d86U, 0x8a8a0f85U, 
    0x7070e090U, 0x3e3e7c42U, 0xb5b571c4U, 0x6666ccaaU, 
    0x484890d8U, 0x03030605U, 0xf6f6f701U, 0x0e0e1c12U, 
    0x6161c2a3U, 0x35356a5fU, 0x5757aef9U, 0xb9b969d0U, 
    0x86861791U, 0xc1c19958U, 0x1d1d3a27U, 0x9e9e27b9U, 
    0xe1e1d938U, 0xf8f8eb13U, 0x98982bb3U, 0x11112233U, 
    0x6969d2bbU, 0xd9d9a970U, 0x8e8e0789U, 0x949433a7U, 
    0x9b9b2db6U, 0x1e1e3c22U, 0x87871592U, 0xe9e9c920U, 
    0xcece8749U, 0x5555aaffU, 0x28285078U, 0xdfdfa57aU, 
    0x8c8c038fU, 0xa1a159f8U, 0x89890980U, 0x0d0d1a17U, 
    0xbfbf65daU, 0xe6e6d731U, 0x424284c6U, 0x6868d0b8U, 
    0x414182c3U, 0x999929b0U, 0x2d2d5a77U, 0x0f0f1e11U, 
    0xb0b07bcbU, 0x5454a8fcU, 0xbbbb6dd6U, 0x16162c3aU, 
};

const uint Te2_r[] = {
    0x63c6a563U, 0x7cf8847cU, 0x77ee9977U, 0x7bf68d7bU, 
    0xf2ff0df2U, 0x6bd6bd6bU, 0x6fdeb16fU, 0xc59154c5U, 
    0x30605030U, 0x01020301U, 0x67cea967U, 0x2b567d2bU, 
    0xfee719feU, 0xd7b562d7U, 0xab4de6abU, 0x76ec9a76U, 
    0xca8f45caU, 0x821f9d82U, 0xc98940c9U, 0x7dfa877dU, 
    0xfaef15faU, 0x59b2eb59U, 0x478ec947U, 0xf0fb0bf0U, 
    0xad41ecadU, 0xd4b367d4U, 0xa25ffda2U, 0xaf45eaafU, 
    0x9c23bf9cU, 0xa453f7a4U, 0x72e49672U, 0xc09b5bc0U, 
    0xb775c2b7U, 0xfde11cfdU, 0x933dae93U, 0x264c6a26U, 
    0x366c5a36U, 0x3f7e413fU, 0xf7f502f7U, 0xcc834fccU, 
    0x34685c34U, 0xa551f4a5U, 0xe5d134e5U, 0xf1f908f1U, 
    0x71e29371U, 0xd8ab73d8U, 0x31625331U, 0x152a3f15U, 
    0x04080c04U, 0xc79552c7U, 0x23466523U, 0xc39d5ec3U, 
    0x18302818U, 0x9637a196U, 0x050a0f05U, 0x9a2fb59aU, 
    0x070e0907U, 0x12243612U, 0x801b9b80U, 0xe2df3de2U, 
    0xebcd26ebU, 0x274e6927U, 0xb27fcdb2U, 0x75ea9f75U, 
    0x09121b09U, 0x831d9e83U, 0x2c58742cU, 0x1a342e1aU, 
    0x1b362d1bU, 0x6edcb26eU, 0x5ab4ee5aU, 0xa05bfba0U, 
    0x52a4f652U, 0x3b764d3bU, 0xd6b761d6U, 0xb37dceb3U, 
    0x29527b29U, 0xe3dd3ee3U, 0x2f5e712fU, 0x84139784U, 
    0x53a6f553U, 0xd1b968d1U, 0x00000000U, 0xedc12cedU, 
    0x20406020U, 0xfce31ffcU, 0xb179c8b1U, 0x5bb6ed5bU, 
    0x6ad4be6aU, 0xcb8d46cbU, 0xbe67d9beU, 0x39724b39U, 
    0x4a94de4aU, 0x4c98d44cU, 0x58b0e858U, 0xcf854acfU, 
    0xd0bb6bd0U, 0xefc52aefU, 0xaa4fe5aaU, 0xfbed16fbU, 
    0x4386c543U, 0x4d9ad74dU, 0x33665533U, 0x85119485U, 
    0x458acf45U, 0xf9e910f9U, 0x02040602U, 0x7ffe817fU, 
    0x50a0f050U, 0x3c78443cU, 0x9f25ba9fU, 0xa84be3a8U, 
    0x51a2f351U, 0xa35dfea3U, 0x4080c040U, 0x8f058a8fU, 
    0x923fad92U, 0x9d21bc9dU, 0x38704838U, 0xf5f104f5U, 
    0xbc63dfbcU, 0xb677c1b6U, 0xdaaf75daU, 0x21426321U, 
    0x10203010U, 0xffe51affU, 0xf3fd0ef3U, 0xd2bf6dd2U, 
    0xcd814ccdU, 0x0c18140cU, 0x13263513U, 0xecc32fecU, 
    0x5fbee15fU, 0x9735a297U, 0x4488cc44U, 0x172e3917U, 
    0xc49357c4U, 0xa755f2a7U, 0x7efc827eU, 0x3d7a473dU, 
    0x64c8ac64U, 0x5dbae75dU, 0x19322b19U, 0x73e69573U, 
    0x60c0a060U, 0x81199881U, 0x4f9ed14fU, 0xdca37fdcU, 
    0x22446622U, 0x2a547e2aU, 0x903bab90U, 0x880b8388U, 
    0x468cca46U, 0xeec729eeU, 0xb86bd3b8U, 0x14283c14U, 
    0xdea779deU, 0x5ebce25eU, 0x0b161d0bU, 0xdbad76dbU, 
    0xe0db3be0U, 0x32645632U, 0x3a744e3aU, 0x0a141e0aU, 
    0x4992db49U, 0x060c0a06U, 0x24486c24U, 0x5cb8e45cU, 
    0xc29f5dc2U, 0xd3bd6ed3U, 0xac43efacU, 0x62c4a662U, 
    0x9139a891U, 0x9531a495U, 0xe4d337e4U, 0x79f28b79U, 
    0xe7d532e7U, 0xc88b43c8U, 0x376e5937U, 0x6ddab76dU, 
    0x8d018c8dU, 0xd5b164d5U, 0x4e9cd24eU, 0xa949e0a9U, 
    0x6cd8b46cU, 0x56acfa56U, 0xf4f307f4U, 0xeacf25eaU, 
    0x65caaf65U, 0x7af48e7aU, 0xae47e9aeU, 0x08101808U, 
    0xba6fd5baU, 0x78f08878U, 0x254a6f25U, 0x2e5c722eU, 
    0x1c38241cU, 0xa657f1a6U, 0xb473c7b4U, 0xc69751c6U, 
    0xe8cb23e8U, 0xdda17cddU, 0x74e89c74U, 0x1f3e211fU, 
    0x4b96dd4bU, 0xbd61dcbdU, 0x8b0d868bU, 0x8a0f858aU, 
    0x70e09070U, 0x3e7c423eU, 0xb571c4b5U, 0x66ccaa66U, 
    0x4890d848U, 0x03060503U, 0xf6f701f6U, 0x0e1c120eU, 
    0x61c2a361U, 0x356a5f35U, 0x57aef957U, 0xb969d0b9U, 
    0x86179186U, 0xc19958c1U, 0x1d3a271dU, 0x9e27b99eU, 
    0xe1d938e1U, 0xf8eb13f8U, 0x982bb398U, 0x11223311U, 
    0x69d2bb69U, 0xd9a970d9U, 0x8e07898eU, 0x9433a794U, 
    0x9b2db69bU, 0x1e3c221eU, 0x87159287U, 0xe9c920e9U, 
    0xce8749ceU, 0x55aaff55U, 0x28507828U, 0xdfa57adfU, 
    0x8c038f8cU, 0xa159f8a1U, 0x89098089U, 0x0d1a170dU, 
    0xbf65dabfU, 0xe6d731e6U, 0x4284c642U, 0x68d0b868U, 
    0x4182c341U, 0x9929b099U, 0x2d5a772dU, 0x0f1e110fU, 
    0xb07bcbb0U, 0x54a8fc54U, 0xbb6dd6bbU, 0x162c3a16U, 
};

const uint Te3_r[] = {
    0xc6a56363U, 0xf8847c7cU, 0xee997777U, 0xf68d7b7bU, 
    0xff0df2f2U, 0xd6bd6b6bU, 0xdeb16f6fU, 0x9154c5c5U, 
    0x60503030U, 0x02030101U, 0xcea96767U, 0x567d2b2bU, 
    0xe719fefeU, 0xb562d7d7U, 0x4de6ababU, 0xec9a7676U, 
    0x8f45cacaU, 0x1f9d8282U, 0x8940c9c9U, 0xfa877d7dU, 
    0xef15fafaU, 0xb2eb5959U, 0x8ec94747U, 0xfb0bf0f0U, 
    0x41ecadadU, 0xb367d4d4U, 0x5ffda2a2U, 0x45eaafafU, 
    0x23bf9c9cU, 0x53f7a4a4U, 0xe4967272U, 0x9b5bc0c0U, 
    0x75c2b7b7U, 0xe11cfdfdU, 0x3dae9393U, 0x4c6a2626U, 
    0x6c5a3636U, 0x7e413f3fU, 0xf502f7f7U, 0x834fccccU, 
    0x685c3434U, 0x51f4a5a5U, 0xd134e5e5U, 0xf908f1f1U, 
    0xe2937171U, 0xab73d8d8U, 0x62533131U, 0x2a3f1515U, 
    0x080c0404U, 0x9552c7c7U, 0x46652323U, 0x9d5ec3c3U, 
    0x30281818U, 0x37a19696U, 0x0a0f0505U, 0x2fb59a9aU, 
    0x0e090707U, 0x24361212U, 0x1b9b8080U, 0xdf3de2e2U, 
    0xcd26ebebU, 0x4e692727U, 0x7fcdb2b2U, 0xea9f7575U, 
    0x121b0909U, 0x1d9e8383U, 0x58742c2cU, 0x342e1a1aU, 
    0x362d1b1bU, 0xdcb26e6eU, 0xb4ee5a5aU, 0x5bfba0a0U, 
    0xa4f65252U, 0x764d3b3bU, 0xb761d6d6U, 0x7dceb3b3U, 
    0x527b2929U, 0xdd3ee3e3U, 0x5e712f2fU, 0x13978484U, 
    0xa6f55353U, 0xb968d1d1U, 0x00000000U, 0xc12cededU, 
    0x40602020U, 0xe31ffcfcU, 0x79c8b1b1U, 0xb6ed5b5bU, 
    0xd4be6a6aU, 0x8d46cbcbU, 0x67d9bebeU, 0x724b3939U, 
    0x94de4a4aU, 0x98d44c4cU, 0xb0e85858U, 0x854acfcfU, 
    0xbb6bd0d0U, 0xc52aefefU, 0x4fe5aaaaU, 0xed16fbfbU, 
    0x86c54343U, 0x9ad74d4dU, 0x66553333U, 0x11948585U, 
    0x8acf4545U, 0xe910f9f9U, 0x04060202U, 0xfe817f7fU, 
    0xa0f05050U, 0x78443c3cU, 0x25ba9f9fU, 0x4be3a8a8U, 
    0xa2f35151U, 0x5dfea3a3U, 0x80c04040U, 0x058a8f8fU, 
    0x3fad9292U, 0x21bc9d9dU, 0x70483838U, 0xf104f5f5U, 
    0x63dfbcbcU, 0x77c1b6b6U, 0xaf75dadaU, 0x42632121U, 
    0x20301010U, 0xe51affffU, 0xfd0ef3f3U, 0xbf6dd2d2U, 
    0x814ccdcdU, 0x18140c0cU, 0x26351313U, 0xc32fececU, 
    0xbee15f5fU, 0x35a29797U, 0x88cc4444U, 0x2e391717U, 
    0x9357c4c4U, 0x55f2a7a7U, 0xfc827e7eU, 0x7a473d3dU, 
    0xc8ac6464U, 0xbae75d5dU, 0x322b1919U, 0xe6957373U, 
    0xc0a06060U, 0x19988181U, 0x9ed14f4fU, 0xa37fdcdcU, 
    0x44662222U, 0x547e2a2aU, 0x3bab9090U, 0x0b838888U, 
    0x8cca4646U, 0xc729eeeeU, 0x6bd3b8b8U, 0x283c1414U, 
    0xa779dedeU, 0xbce25e5eU, 0x161d0b0bU, 0xad76dbdbU, 
    0xdb3be0e0U, 0x64563232U, 0x744e3a3aU, 0x141e0a0aU, 
    0x92db4949U, 0x0c0a0606U, 0x486c2424U, 0xb8e45c5cU, 
    0x9f5dc2c2U, 0xbd6ed3d3U, 0x43efacacU, 0xc4a66262U, 
    0x39a89191U, 0x31a49595U, 0xd337e4e4U, 0xf28b7979U, 
    0xd532e7e7U, 0x8b43c8c8U, 0x6e593737U, 0xdab76d6dU, 
    0x018c8d8dU, 0xb164d5d5U, 0x9cd24e4eU, 0x49e0a9a9U, 
    0xd8b46c6cU, 0xacfa5656U, 0xf307f4f4U, 0xcf25eaeaU, 
    0xcaaf6565U, 0xf48e7a7aU, 0x47e9aeaeU, 0x10180808U, 
    0x6fd5babaU, 0xf0887878U, 0x4a6f2525U, 0x5c722e2eU, 
    0x38241c1cU, 0x57f1a6a6U, 0x73c7b4b4U, 0x9751c6c6U, 
    0xcb23e8e8U, 0xa17cddddU, 0xe89c7474U, 0x3e211f1fU, 
    0x96dd4b4bU, 0x61dcbdbdU, 0x0d868b8bU, 0x0f858a8aU, 
    0xe0907070U, 0x7c423e3eU, 0x71c4b5b5U, 0xccaa6666U, 
    0x90d84848U, 0x06050303U, 0xf701f6f6U, 0x1c120e0eU, 
    0xc2a36161U, 0x6a5f3535U, 0xaef95757U, 0x69d0b9b9U, 
    0x17918686U, 0x9958c1c1U, 0x3a271d1dU, 0x27b99e9eU, 
    0xd938e1e1U, 0xeb13f8f8U, 0x2bb39898U, 0x22331111U, 
    0xd2bb6969U, 0xa970d9d9U, 0x07898e8eU, 0x33a79494U, 
    0x2db69b9bU, 0x3c221e1eU, 0x15928787U, 0xc920e9e9U, 
    0x8749ceceU, 0xaaff5555U, 0x50782828U, 0xa57adfdfU, 
    0x038f8c8cU, 0x59f8a1a1U, 0x09808989U, 0x1a170d0dU, 
    0x65dabfbfU, 0xd731e6e6U, 0x84c64242U, 0xd0b86868U, 
    0x82c34141U, 0x29b09999U, 0x5a772d2dU, 0x1e110f0fU, 
    0x7bcbb0b0U, 0xa8fc5454U, 0x6dd6bbbbU, 0x2c3a1616U, 
};

const uint Td0_r[] = {
    0x50a7f451U, 0x5365417eU, 0xc3a4171aU, 0x965e273aU, 
    0xcb6bab3bU, 0xf1459d1fU, 0xab58faacU, 0x9303e34bU, 
    0x55fa3020U, 0xf66d76adU, 0x9176cc88U, 0x254c02f5U, 
    0xfcd7e54fU, 0xd7cb2ac5U, 0x80443526U, 0x8fa362b5U, 
    0x495ab1deU, 0x671bba25U, 0x980eea45U, 0xe1c0fe5dU, 
    0x02752fc3U, 0x12f04c81U, 0xa397468dU, 0xc6f9d36bU, 
    0xe75f8f03U, 0x959c9215U, 0xeb7a6dbfU, 0xda595295U, 
    0x2d83bed4U, 0xd3217458U, 0x2969e049U, 0x44c8c98eU, 
    0x6a89c275U, 0x78798ef4U, 0x6b3e5899U, 0xdd71b927U, 
    0xb64fe1beU, 0x17ad88f0U, 0x66ac20c9U, 0xb43ace7dU, 
    0x184adf63U, 0x82311ae5U, 0x60335197U, 0x457f5362U, 
    0xe07764b1U, 0x84ae6bbbU, 0x1ca081feU, 0x942b08f9U, 
    0x58684870U, 0x19fd458fU, 0x876cde94U, 0xb7f87b52U, 
    0x23d373abU, 0xe2024b72U, 0x578f1fe3U, 0x2aab5566U, 
    0x0728ebb2U, 0x03c2b52fU, 0x9a7bc586U, 0xa50837d3U, 
    0xf2872830U, 0xb2a5bf23U, 0xba6a0302U, 0x5c8216edU, 
    0x2b1ccf8aU, 0x92b479a7U, 0xf0f207f3U, 0xa1e2694eU, 
    0xcdf4da65U, 0xd5be0506U, 0x1f6234d1U, 0x8afea6c4U, 
    0x9d532e34U, 0xa055f3a2U, 0x32e18a05U, 0x75ebf6a4U, 
    0x39ec830bU, 0xaaef6040U, 0x069f715eU, 0x51106ebdU, 
    0xf98a213eU, 0x3d06dd96U, 0xae053eddU, 0x46bde64dU, 
    0xb58d5491U, 0x055dc471U, 0x6fd40604U, 0xff155060U, 
    0x24fb9819U, 0x97e9bdd6U, 0xcc434089U, 0x779ed967U, 
    0xbd42e8b0U, 0x888b8907U, 0x385b19e7U, 0xdbeec879U, 
    0x470a7ca1U, 0xe90f427cU, 0xc91e84f8U, 0x00000000U, 
    0x83868009U, 0x48ed2b32U, 0xac70111eU, 0x4e725a6cU, 
    0xfbff0efdU, 0x5638850fU, 0x1ed5ae3dU, 0x27392d36U, 
    0x64d90f0aU, 0x21a65c68U, 0xd1545b9bU, 0x3a2e3624U, 
    0xb1670a0cU, 0x0fe75793U, 0xd296eeb4U, 0x9e919b1bU, 
    0x4fc5c080U, 0xa220dc61U, 0x694b775aU, 0x161a121cU, 
    0x0aba93e2U, 0xe52aa0c0U, 0x43e0223cU, 0x1d171b12U, 
    0x0b0d090eU, 0xadc78bf2U, 0xb9a8b62dU, 0xc8a91e14U, 
    0x8519f157U, 0x4c0775afU, 0xbbdd99eeU, 0xfd607fa3U, 
    0x9f2601f7U, 0xbcf5725cU, 0xc53b6644U, 0x347efb5bU, 
    0x7629438bU, 0xdcc623cbU, 0x68fcedb6U, 0x63f1e4b8U, 
    0xcadc31d7U, 0x10856342U, 0x40229713U, 0x2011c684U, 
    0x7d244a85U, 0xf83dbbd2U, 0x1132f9aeU, 0x6da129c7U, 
    0x4b2f9e1dU, 0xf330b2dcU, 0xec52860dU, 0xd0e3c177U, 
    0x6c16b32bU, 0x99b970a9U, 0xfa489411U, 0x2264e947U, 
    0xc48cfca8U, 0x1a3ff0a0U, 0xd82c7d56U, 0xef903322U, 
    0xc74e4987U, 0xc1d138d9U, 0xfea2ca8cU, 0x360bd498U, 
    0xcf81f5a6U, 0x28de7aa5U, 0x268eb7daU, 0xa4bfad3fU, 
    0xe49d3a2cU, 0x0d927850U, 0x9bcc5f6aU, 0x62467e54U, 
    0xc2138df6U, 0xe8b8d890U, 0x5ef7392eU, 0xf5afc382U, 
    0xbe805d9fU, 0x7c93d069U, 0xa92dd56fU, 0xb31225cfU, 
    0x3b99acc8U, 0xa77d1810U, 0x6e639ce8U, 0x7bbb3bdbU, 
    0x097826cdU, 0xf418596eU, 0x01b79aecU, 0xa89a4f83U, 
    0x656e95e6U, 0x7ee6ffaaU, 0x08cfbc21U, 0xe6e815efU, 
    0xd99be7baU, 0xce366f4aU, 0xd4099feaU, 0xd67cb029U, 
    0xafb2a431U, 0x31233f2aU, 0x3094a5c6U, 0xc066a235U, 
    0x37bc4e74U, 0xa6ca82fcU, 0xb0d090e0U, 0x15d8a733U, 
    0x4a9804f1U, 0xf7daec41U, 0x0e50cd7fU, 0x2ff69117U, 
    0x8dd64d76U, 0x4db0ef43U, 0x544daaccU, 0xdf0496e4U, 
    0xe3b5d19eU, 0x1b886a4cU, 0xb81f2cc1U, 0x7f516546U, 
    0x04ea5e9dU, 0x5d358c01U, 0x737487faU, 0x2e410bfbU, 
    0x5a1d67b3U, 0x52d2db92U, 0x335610e9U, 0x1347d66dU, 
    0x8c61d79aU, 0x7a0ca137U, 0x8e14f859U, 0x893c13ebU, 
    0xee27a9ceU, 0x35c961b7U, 0xede51ce1U, 0x3cb1477aU, 
    0x59dfd29cU, 0x3f73f255U, 0x79ce1418U, 0xbf37c773U, 
    0xeacdf753U, 0x5baafd5fU, 0x146f3ddfU, 0x86db4478U, 
    0x81f3afcaU, 0x3ec468b9U, 0x2c342438U, 0x5f40a3c2U, 
    0x72c31d16U, 0x0c25e2bcU, 0x8b493c28U, 0x41950dffU, 
    0x7101a839U, 0xdeb30c08U, 0x9ce4b4d8U, 0x90c15664U, 
    0x6184cb7bU, 0x70b632d5U, 0x745c6c48U, 0x4257b8d0U, 
};

const uint Td1_r[] = {
    0xA7F45150U, 0x65417E53U, 0xA4171AC3U, 0x5E273A96U, 
    0x6BAB3BCBU, 0x459D1FF1U, 0x58FAACABU, 0x03E34B93U, 
    0xFA302055U, 0x6D76ADF6U, 0x76CC8891U, 0x4C02F525U, 
    0xD7E54FFCU, 0xCB2AC5D7U, 0x44352680U, 0xA362B58FU, 
    0x5AB1DE49U, 0x1BBA2567U, 0x0EEA4598U, 0xC0FE5DE1U, 
    0x752FC302U, 0xF04C8112U, 0x97468DA3U, 0xF9D36BC6U, 
    0x5F8F03E7U, 0x9C921595U, 0x7A6DBFEBU, 0x595295DAU, 
    0x83BED42DU, 0x217458D3U, 0x69E04929U, 0xC8C98E44U, 
    0x89C2756AU, 0x798EF478U, 0x3E58996BU, 0x71B927DDU, 
    0x4FE1BEB6U, 0xAD88F017U, 0xAC20C966U, 0x3ACE7DB4U, 
    0x4ADF6318U, 0x311AE582U, 0x33519760U, 0x7F536245U, 
    0x7764B1E0U, 0xAE6BBB84U, 0xA081FE1CU, 0x2B08F994U, 
    0x68487058U, 0xFD458F19U, 0x6CDE9487U, 0xF87B52B7U, 
    0xD373AB23U, 0x024B72E2U, 0x8F1FE357U, 0xAB55662AU, 
    0x28EBB207U, 0xC2B52F03U, 0x7BC5869AU, 0x0837D3A5U, 
    0x872830F2U, 0xA5BF23B2U, 0x6A0302BAU, 0x8216ED5CU, 
    0x1CCF8A2BU, 0xB479A792U, 0xF207F3F0U, 0xE2694EA1U, 
    0xF4DA65CDU, 0xBE0506D5U, 0x6234D11FU, 0xFEA6C48AU, 
    0x532E349DU, 0x55F3A2A0U, 0xE18A0532U, 0xEBF6A475U, 
    0xEC830B39U, 0xEF6040AAU, 0x9F715E06U, 0x106EBD51U, 
    0x8A213EF9U, 0x06DD963DU, 0x053EDDAEU, 0xBDE64D46U, 
    0x8D5491B5U, 0x5DC47105U, 0xD406046FU, 0x155060FFU, 
    0xFB981924U, 0xE9BDD697U, 0x434089CCU, 0x9ED96777U, 
    0x42E8B0BDU, 0x8B890788U, 0x5B19E738U, 0xEEC879DBU, 
    0x0A7CA147U, 0x0F427CE9U, 0x1E84F8C9U, 0x00000000U, 
    0x86800983U, 0xED2B3248U, 0x70111EACU, 0x725A6C4EU, 
    0xFF0EFDFBU, 0x38850F56U, 0xD5AE3D1EU, 0x392D3627U, 
    0xD90F0A64U, 0xA65C6821U, 0x545B9BD1U, 0x2E36243AU, 
    0x670A0CB1U, 0xE757930FU, 0x96EEB4D2U, 0x919B1B9EU, 
    0xC5C0804FU, 0x20DC61A2U, 0x4B775A69U, 0x1A121C16U, 
    0xBA93E20AU, 0x2AA0C0E5U, 0xE0223C43U, 0x171B121DU, 
    0x0D090E0BU, 0xC78BF2ADU, 0xA8B62DB9U, 0xA91E14C8U, 
    0x19F15785U, 0x0775AF4CU, 0xDD99EEBBU, 0x607FA3FDU, 
    0x2601F79FU, 0xF5725CBCU, 0x3B6644C5U, 0x7EFB5B34U, 
    0x29438B76U, 0xC623CBDCU, 0xFCEDB668U, 0xF1E4B863U, 
    0xDC31D7CAU, 0x85634210U, 0x22971340U, 0x11C68420U, 
    0x244A857DU, 0x3DBBD2F8U, 0x32F9AE11U, 0xA129C76DU, 
    0x2F9E1D4BU, 0x30B2DCF3U, 0x52860DECU, 0xE3C177D0U, 
    0x16B32B6CU, 0xB970A999U, 0x489411FAU, 0x64E94722U, 
    0x8CFCA8C4U, 0x3FF0A01AU, 0x2C7D56D8U, 0x903322EFU, 
    0x4E4987C7U, 0xD138D9C1U, 0xA2CA8CFEU, 0x0BD49836U, 
    0x81F5A6CFU, 0xDE7AA528U, 0x8EB7DA26U, 0xBFAD3FA4U, 
    0x9D3A2CE4U, 0x9278500DU, 0xCC5F6A9BU, 0x467E5462U, 
    0x138DF6C2U, 0xB8D890E8U, 0xF7392E5EU, 0xAFC382F5U, 
    0x805D9FBEU, 0x93D0697CU, 0x2DD56FA9U, 0x1225CFB3U, 
    0x99ACC83BU, 0x7D1810A7U, 0x639CE86EU, 0xBB3BDB7BU, 
    0x7826CD09U, 0x18596EF4U, 0xB79AEC01U, 0x9A4F83A8U, 
    0x6E95E665U, 0xE6FFAA7EU, 0xCFBC2108U, 0xE815EFE6U, 
    0x9BE7BAD9U, 0x366F4ACEU, 0x099FEAD4U, 0x7CB029D6U, 
    0xB2A431AFU, 0x233F2A31U, 0x94A5C630U, 0x66A235C0U, 
    0xBC4E7437U, 0xCA82FCA6U, 0xD090E0B0U, 0xD8A73315U, 
    0x9804F14AU, 0xDAEC41F7U, 0x50CD7F0EU, 0xF691172FU, 
    0xD64D768DU, 0xB0EF434DU, 0x4DAACC54U, 0x0496E4DFU, 
    0xB5D19EE3U, 0x886A4C1BU, 0x1F2CC1B8U, 0x5165467FU, 
    0xEA5E9D04U, 0x358C015DU, 0x7487FA73U, 0x410BFB2EU, 
    0x1D67B35AU, 0xD2DB9252U, 0x5610E933U, 0x47D66D13U, 
    0x61D79A8CU, 0x0CA1377AU, 0x14F8598EU, 0x3C13EB89U, 
    0x27A9CEEEU, 0xC961B735U, 0xE51CE1EDU, 0xB1477A3CU, 
    0xDFD29C59U, 0x73F2553FU, 0xCE141879U, 0x37C773BFU, 
    0xCDF753EAU, 0xAAFD5F5BU, 0x6F3DDF14U, 0xDB447886U, 
    0xF3AFCA81U, 0xC468B93EU, 0x3424382CU, 0x40A3C25FU, 
    0xC31D1672U, 0x25E2BC0CU, 0x493C288BU, 0x950DFF41U, 
    0x01A83971U, 0xB30C08DEU, 0xE4B4D89CU, 0xC1566490U, 
    0x84CB7B61U, 0xB632D570U, 0x5C6C4874U, 0x57B8D042U, 
};

const uint Td2_r[] = {
    0xF45150A7U, 0x417E5365U, 0x171AC3A4U, 0x273A965EU, 
    0xAB3BCB6BU, 0x9D1FF145U, 0xFAACAB58U, 0xE34B9303U, 
    0x302055FAU, 0x76ADF66DU, 0xCC889176U, 0x02F5254CU, 
    0xE54FFCD7U, 0x2AC5D7CBU, 0x35268044U, 0x62B58FA3U, 
    0xB1DE495AU, 0xBA25671BU, 0xEA45980EU, 0xFE5DE1C0U, 
    0x2FC30275U, 0x4C8112F0U, 0x468DA397U, 0xD36BC6F9U, 
    0x8F03E75FU, 0x9215959CU, 0x6DBFEB7AU, 0x5295DA59U, 
    0xBED42D83U, 0x7458D321U, 0xE0492969U, 0xC98E44C8U, 
    0xC2756A89U, 0x8EF47879U, 0x58996B3EU, 0xB927DD71U, 
    0xE1BEB64FU, 0x88F017ADU, 0x20C966ACU, 0xCE7DB43AU, 
    0xDF63184AU, 0x1AE58231U, 0x51976033U, 0x5362457FU, 
    0x64B1E077U, 0x6BBB84AEU, 0x81FE1CA0U, 0x08F9942BU, 
    0x48705868U, 0x458F19FDU, 0xDE94876CU, 0x7B52B7F8U, 
    0x73AB23D3U, 0x4B72E202U, 0x1FE3578FU, 0x55662AABU, 
    0xEBB20728U, 0xB52F03C2U, 0xC5869A7BU, 0x37D3A508U, 
    0x2830F287U, 0xBF23B2A5U, 0x0302BA6AU, 0x16ED5C82U, 
    0xCF8A2B1CU, 0x79A792B4U, 0x07F3F0F2U, 0x694EA1E2U, 
    0xDA65CDF4U, 0x0506D5BEU, 0x34D11F62U, 0xA6C48AFEU, 
    0x2E349D53U, 0xF3A2A055U, 0x8A0532E1U, 0xF6A475EBU, 
    0x830B39ECU, 0x6040AAEFU, 0x715E069FU, 0x6EBD5110U, 
    0x213EF98AU, 0xDD963D06U, 0x3EDDAE05U, 0xE64D46BDU, 
    0x5491B58DU, 0xC471055DU, 0x06046FD4U, 0x5060FF15U, 
    0x981924FBU, 0xBDD697E9U, 0x4089CC43U, 0xD967779EU, 
    0xE8B0BD42U, 0x8907888BU, 0x19E7385BU, 0xC879DBEEU, 
    0x7CA1470AU, 0x427CE90FU, 0x84F8C91EU, 0x00000000U, 
    0x80098386U, 0x2B3248EDU, 0x111EAC70U, 0x5A6C4E72U, 
    0x0EFDFBFFU, 0x850F5638U, 0xAE3D1ED5U, 0x2D362739U, 
    0x0F0A64D9U, 0x5C6821A6U, 0x5B9BD154U, 0x36243A2EU, 
    0x0A0CB167U, 0x57930FE7U, 0xEEB4D296U, 0x9B1B9E91U, 
    0xC0804FC5U, 0xDC61A220U, 0x775A694BU, 0x121C161AU, 
    0x93E20ABAU, 0xA0C0E52AU, 0x223C43E0U, 0x1B121D17U, 
    0x090E0B0DU, 0x8BF2ADC7U, 0xB62DB9A8U, 0x1E14C8A9U, 
    0xF1578519U, 0x75AF4C07U, 0x99EEBBDDU, 0x7FA3FD60U, 
    0x01F79F26U, 0x725CBCF5U, 0x6644C53BU, 0xFB5B347EU, 
    0x438B7629U, 0x23CBDCC6U, 0xEDB668FCU, 0xE4B863F1U, 
    0x31D7CADCU, 0x63421085U, 0x97134022U, 0xC6842011U, 
    0x4A857D24U, 0xBBD2F83DU, 0xF9AE1132U, 0x29C76DA1U, 
    0x9E1D4B2FU, 0xB2DCF330U, 0x860DEC52U, 0xC177D0E3U, 
    0xB32B6C16U, 0x70A999B9U, 0x9411FA48U, 0xE9472264U, 
    0xFCA8C48CU, 0xF0A01A3FU, 0x7D56D82CU, 0x3322EF90U, 
    0x4987C74EU, 0x38D9C1D1U, 0xCA8CFEA2U, 0xD498360BU, 
    0xF5A6CF81U, 0x7AA528DEU, 0xB7DA268EU, 0xAD3FA4BFU, 
    0x3A2CE49DU, 0x78500D92U, 0x5F6A9BCCU, 0x7E546246U, 
    0x8DF6C213U, 0xD890E8B8U, 0x392E5EF7U, 0xC382F5AFU, 
    0x5D9FBE80U, 0xD0697C93U, 0xD56FA92DU, 0x25CFB312U, 
    0xACC83B99U, 0x1810A77DU, 0x9CE86E63U, 0x3BDB7BBBU, 
    0x26CD0978U, 0x596EF418U, 0x9AEC01B7U, 0x4F83A89AU, 
    0x95E6656EU, 0xFFAA7EE6U, 0xBC2108CFU, 0x15EFE6E8U, 
    0xE7BAD99BU, 0x6F4ACE36U, 0x9FEAD409U, 0xB029D67CU, 
    0xA431AFB2U, 0x3F2A3123U, 0xA5C63094U, 0xA235C066U, 
    0x4E7437BCU, 0x82FCA6CAU, 0x90E0B0D0U, 0xA73315D8U, 
    0x04F14A98U, 0xEC41F7DAU, 0xCD7F0E50U, 0x91172FF6U, 
    0x4D768DD6U, 0xEF434DB0U, 0xAACC544DU, 0x96E4DF04U, 
    0xD19EE3B5U, 0x6A4C1B88U, 0x2CC1B81FU, 0x65467F51U, 
    0x5E9D04EAU, 0x8C015D35U, 0x87FA7374U, 0x0BFB2E41U, 
    0x67B35A1DU, 0xDB9252D2U, 0x10E93356U, 0xD66D1347U, 
    0xD79A8C61U, 0xA1377A0CU, 0xF8598E14U, 0x13EB893CU, 
    0xA9CEEE27U, 0x61B735C9U, 0x1CE1EDE5U, 0x477A3CB1U, 
    0xD29C59DFU, 0xF2553F73U, 0x141879CEU, 0xC773BF37U, 
    0xF753EACDU, 0xFD5F5BAAU, 0x3DDF146FU, 0x447886DBU, 
    0xAFCA81F3U, 0x68B93EC4U, 0x24382C34U, 0xA3C25F40U, 
    0x1D1672C3U, 0xE2BC0C25U, 0x3C288B49U, 0x0DFF4195U, 
    0xA8397101U, 0x0C08DEB3U, 0xB4D89CE4U, 0x566490C1U, 
    0xCB7B6184U, 0x32D570B6U, 0x6C48745CU, 0xB8D04257U, 
};

const uint Td3_r[] = {
    0x5150A7F4U, 0x7E536541U, 0x1AC3A417U, 0x3A965E27U, 
    0x3BCB6BABU, 0x1FF1459DU, 0xACAB58FAU, 0x4B9303E3U, 
    0x2055FA30U, 0xADF66D76U, 0x889176CCU, 0xF5254C02U, 
    0x4FFCD7E5U, 0xC5D7CB2AU, 0x26804435U, 0xB58FA362U, 
    0xDE495AB1U, 0x25671BBAU, 0x45980EEAU, 0x5DE1C0FEU, 
    0xC302752FU, 0x8112F04CU, 0x8DA39746U, 0x6BC6F9D3U, 
    0x03E75F8FU, 0x15959C92U, 0xBFEB7A6DU, 0x95DA5952U, 
    0xD42D83BEU, 0x58D32174U, 0x492969E0U, 0x8E44C8C9U, 
    0x756A89C2U, 0xF478798EU, 0x996B3E58U, 0x27DD71B9U, 
    0xBEB64FE1U, 0xF017AD88U, 0xC966AC20U, 0x7DB43ACEU, 
    0x63184ADFU, 0xE582311AU, 0x97603351U, 0x62457F53U, 
    0xB1E07764U, 0xBB84AE6BU, 0xFE1CA081U, 0xF9942B08U, 
    0x70586848U, 0x8F19FD45U, 0x94876CDEU, 0x52B7F87BU, 
    0xAB23D373U, 0x72E2024BU, 0xE3578F1FU, 0x662AAB55U, 
    0xB20728EBU, 0x2F03C2B5U, 0x869A7BC5U, 0xD3A50837U, 
    0x30F28728U, 0x23B2A5BFU, 0x02BA6A03U, 0xED5C8216U, 
    0x8A2B1CCFU, 0xA792B479U, 0xF3F0F207U, 0x4EA1E269U, 
    0x65CDF4DAU, 0x06D5BE05U, 0xD11F6234U, 0xC48AFEA6U, 
    0x349D532EU, 0xA2A055F3U, 0x0532E18AU, 0xA475EBF6U, 
    0x0B39EC83U, 0x40AAEF60U, 0x5E069F71U, 0xBD51106EU, 
    0x3EF98A21U, 0x963D06DDU, 0xDDAE053EU, 0x4D46BDE6U, 
    0x91B58D54U, 0x71055DC4U, 0x046FD406U, 0x60FF1550U, 
    0x1924FB98U, 0xD697E9BDU, 0x89CC4340U, 0x67779ED9U, 
    0xB0BD42E8U, 0x07888B89U, 0xE7385B19U, 0x79DBEEC8U, 
    0xA1470A7CU, 0x7CE90F42U, 0xF8C91E84U, 0x00000000U, 
    0x09838680U, 0x3248ED2BU, 0x1EAC7011U, 0x6C4E725AU, 
    0xFDFBFF0EU, 0x0F563885U, 0x3D1ED5AEU, 0x3627392DU, 
    0x0A64D90FU, 0x6821A65CU, 0x9BD1545BU, 0x243A2E36U, 
    0x0CB1670AU, 0x930FE757U, 0xB4D296EEU, 0x1B9E919BU, 
    0x804FC5C0U, 0x61A220DCU, 0x5A694B77U, 0x1C161A12U, 
    0xE20ABA93U, 0xC0E52AA0U, 0x3C43E022U, 0x121D171BU, 
    0x0E0B0D09U, 0xF2ADC78BU, 0x2DB9A8B6U, 0x14C8A91EU, 
    0x578519F1U, 0xAF4C0775U, 0xEEBBDD99U, 0xA3FD607FU, 
    0xF79F2601U, 0x5CBCF572U, 0x44C53B66U, 0x5B347EFBU, 
    0x8B762943U, 0xCBDCC623U, 0xB668FCEDU, 0xB863F1E4U, 
    0xD7CADC31U, 0x42108563U, 0x13402297U, 0x842011C6U, 
    0x857D244AU, 0xD2F83DBBU, 0xAE1132F9U, 0xC76DA129U, 
    0x1D4B2F9EU, 0xDCF330B2U, 0x0DEC5286U, 0x77D0E3C1U, 
    0x2B6C16B3U, 0xA999B970U, 0x11FA4894U, 0x472264E9U, 
    0xA8C48CFCU, 0xA01A3FF0U, 0x56D82C7DU, 0x22EF9033U, 
    0x87C74E49U, 0xD9C1D138U, 0x8CFEA2CAU, 0x98360BD4U, 
    0xA6CF81F5U, 0xA528DE7AU, 0xDA268EB7U, 0x3FA4BFADU, 
    0x2CE49D3AU, 0x500D9278U, 0x6A9BCC5FU, 0x5462467EU, 
    0xF6C2138DU, 0x90E8B8D8U, 0x2E5EF739U, 0x82F5AFC3U, 
    0x9FBE805DU, 0x697C93D0U, 0x6FA92DD5U, 0xCFB31225U, 
    0xC83B99ACU, 0x10A77D18U, 0xE86E639CU, 0xDB7BBB3BU, 
    0xCD097826U, 0x6EF41859U, 0xEC01B79AU, 0x83A89A4FU, 
    0xE6656E95U, 0xAA7EE6FFU, 0x2108CFBCU, 0xEFE6E815U, 
    0xBAD99BE7U, 0x4ACE366FU, 0xEAD4099FU, 0x29D67CB0U, 
    0x31AFB2A4U, 0x2A31233FU, 0xC63094A5U, 0x35C066A2U, 
    0x7437BC4EU, 0xFCA6CA82U, 0xE0B0D090U, 0x3315D8A7U, 
    0xF14A9804U, 0x41F7DAECU, 0x7F0E50CDU, 0x172FF691U, 
    0x768DD64DU, 0x434DB0EFU, 0xCC544DAAU, 0xE4DF0496U, 
    0x9EE3B5D1U, 0x4C1B886AU, 0xC1B81F2CU, 0x467F5165U, 
    0x9D04EA5EU, 0x015D358CU, 0xFA737487U, 0xFB2E410BU, 
    0xB35A1D67U, 0x9252D2DBU, 0xE9335610U, 0x6D1347D6U, 
    0x9A8C61D7U, 0x377A0CA1U, 0x598E14F8U, 0xEB893C13U, 
    0xCEEE27A9U, 0xB735C961U, 0xE1EDE51CU, 0x7A3CB147U, 
    0x9C59DFD2U, 0x553F73F2U, 0x1879CE14U, 0x73BF37C7U, 
    0x53EACDF7U, 0x5F5BAAFDU, 0xDF146F3DU, 0x7886DB44U, 
    0xCA81F3AFU, 0xB93EC468U, 0x382C3424U, 0xC25F40A3U, 
    0x1672C31DU, 0xBC0C25E2U, 0x288B493CU, 0xFF41950DU, 
    0x397101A8U, 0x08DEB30CU, 0xD89CE4B4U, 0x6490C156U, 
    0x7B6184CBU, 0xD570B632U, 0x48745C6CU, 0xD04257B8U, 
};

#endif
