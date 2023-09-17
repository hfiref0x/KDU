/**
 * The Whirlpool hashing function.
 *
 * <P>
 * <b>References</b>
 *
 * <P>
 * The Whirlpool algorithm was developed by
 * <a href="mailto:pbarreto@scopus.com.br">Paulo S. L. M. Barreto</a> and
 * <a href="mailto:vincent.rijmen@cryptomathic.com">Vincent Rijmen</a>.
 *
 * See
 *      P.S.L.M. Barreto, V. Rijmen,
 *      ``The Whirlpool hashing function,''
 *      NESSIE submission, 2000 (tweaked version, 2001),
 *      <https://www.cosic.esat.kuleuven.ac.be/nessie/workshop/submissions/whirlpool.zip>
 *
 * @author  Paulo S.L.M. Barreto
 * @author  Vincent Rijmen.
 *
 * @version 3.0 (2003.03.12)
 *
 * =============================================================================
 *
 * Differences from version 2.1:
 *
 * - Suboptimal diffusion matrix replaced by cir(1, 1, 4, 1, 8, 5, 2, 9).
 *
 * =============================================================================
 *
 * Differences from version 2.0:
 *
 * - Generation of ISO/IEC 10118-3 test vectors.
 * - Bug fix: nonzero carry was ignored when tallying the data length
 *      (this bug apparently only manifested itself when feeding data
 *      in pieces rather than in a single chunk at once).
 * - Support for MS Visual C++ 64-bit integer arithmetic.
 *
 * Differences from version 1.0:
 *
 * - Original S-box replaced by the tweaked, hardware-efficient version.
 *
 * =============================================================================
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Whirlpool.h"
#include "nessie.h"

 /* #define TRACE_INTERMEDIATE_VALUES */

 /*
  * The number of rounds of the internal dedicated block cipher.
  */
#define R 10

  /*
   * Though Whirlpool is endianness-neutral, the encryption tables are listed
   * in BIG-ENDIAN format, which is adopted throughout this implementation
   * (but little-endian notation would be equally suitable if consistently
   * employed).
   */

//
// KDU modififed to shutup MSVC.
//
#if defined (_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 4245)
#pragma warning(disable: 26451)
#endif

static const u64 C0[256] = {
    LL(0x18186018c07830d8), LL(0x23238c2305af4626), LL(0xc6c63fc67ef991b8), LL(0xe8e887e8136fcdfb),
    LL(0x878726874ca113cb), LL(0xb8b8dab8a9626d11), LL(0x0101040108050209), LL(0x4f4f214f426e9e0d),
    LL(0x3636d836adee6c9b), LL(0xa6a6a2a6590451ff), LL(0xd2d26fd2debdb90c), LL(0xf5f5f3f5fb06f70e),
    LL(0x7979f979ef80f296), LL(0x6f6fa16f5fcede30), LL(0x91917e91fcef3f6d), LL(0x52525552aa07a4f8),
    LL(0x60609d6027fdc047), LL(0xbcbccabc89766535), LL(0x9b9b569baccd2b37), LL(0x8e8e028e048c018a),
    LL(0xa3a3b6a371155bd2), LL(0x0c0c300c603c186c), LL(0x7b7bf17bff8af684), LL(0x3535d435b5e16a80),
    LL(0x1d1d741de8693af5), LL(0xe0e0a7e05347ddb3), LL(0xd7d77bd7f6acb321), LL(0xc2c22fc25eed999c),
    LL(0x2e2eb82e6d965c43), LL(0x4b4b314b627a9629), LL(0xfefedffea321e15d), LL(0x575741578216aed5),
    LL(0x15155415a8412abd), LL(0x7777c1779fb6eee8), LL(0x3737dc37a5eb6e92), LL(0xe5e5b3e57b56d79e),
    LL(0x9f9f469f8cd92313), LL(0xf0f0e7f0d317fd23), LL(0x4a4a354a6a7f9420), LL(0xdada4fda9e95a944),
    LL(0x58587d58fa25b0a2), LL(0xc9c903c906ca8fcf), LL(0x2929a429558d527c), LL(0x0a0a280a5022145a),
    LL(0xb1b1feb1e14f7f50), LL(0xa0a0baa0691a5dc9), LL(0x6b6bb16b7fdad614), LL(0x85852e855cab17d9),
    LL(0xbdbdcebd8173673c), LL(0x5d5d695dd234ba8f), LL(0x1010401080502090), LL(0xf4f4f7f4f303f507),
    LL(0xcbcb0bcb16c08bdd), LL(0x3e3ef83eedc67cd3), LL(0x0505140528110a2d), LL(0x676781671fe6ce78),
    LL(0xe4e4b7e47353d597), LL(0x27279c2725bb4e02), LL(0x4141194132588273), LL(0x8b8b168b2c9d0ba7),
    LL(0xa7a7a6a7510153f6), LL(0x7d7de97dcf94fab2), LL(0x95956e95dcfb3749), LL(0xd8d847d88e9fad56),
    LL(0xfbfbcbfb8b30eb70), LL(0xeeee9fee2371c1cd), LL(0x7c7ced7cc791f8bb), LL(0x6666856617e3cc71),
    LL(0xdddd53dda68ea77b), LL(0x17175c17b84b2eaf), LL(0x4747014702468e45), LL(0x9e9e429e84dc211a),
    LL(0xcaca0fca1ec589d4), LL(0x2d2db42d75995a58), LL(0xbfbfc6bf9179632e), LL(0x07071c07381b0e3f),
    LL(0xadad8ead012347ac), LL(0x5a5a755aea2fb4b0), LL(0x838336836cb51bef), LL(0x3333cc3385ff66b6),
    LL(0x636391633ff2c65c), LL(0x02020802100a0412), LL(0xaaaa92aa39384993), LL(0x7171d971afa8e2de),
    LL(0xc8c807c80ecf8dc6), LL(0x19196419c87d32d1), LL(0x494939497270923b), LL(0xd9d943d9869aaf5f),
    LL(0xf2f2eff2c31df931), LL(0xe3e3abe34b48dba8), LL(0x5b5b715be22ab6b9), LL(0x88881a8834920dbc),
    LL(0x9a9a529aa4c8293e), LL(0x262698262dbe4c0b), LL(0x3232c8328dfa64bf), LL(0xb0b0fab0e94a7d59),
    LL(0xe9e983e91b6acff2), LL(0x0f0f3c0f78331e77), LL(0xd5d573d5e6a6b733), LL(0x80803a8074ba1df4),
    LL(0xbebec2be997c6127), LL(0xcdcd13cd26de87eb), LL(0x3434d034bde46889), LL(0x48483d487a759032),
    LL(0xffffdbffab24e354), LL(0x7a7af57af78ff48d), LL(0x90907a90f4ea3d64), LL(0x5f5f615fc23ebe9d),
    LL(0x202080201da0403d), LL(0x6868bd6867d5d00f), LL(0x1a1a681ad07234ca), LL(0xaeae82ae192c41b7),
    LL(0xb4b4eab4c95e757d), LL(0x54544d549a19a8ce), LL(0x93937693ece53b7f), LL(0x222288220daa442f),
    LL(0x64648d6407e9c863), LL(0xf1f1e3f1db12ff2a), LL(0x7373d173bfa2e6cc), LL(0x12124812905a2482),
    LL(0x40401d403a5d807a), LL(0x0808200840281048), LL(0xc3c32bc356e89b95), LL(0xecec97ec337bc5df),
    LL(0xdbdb4bdb9690ab4d), LL(0xa1a1bea1611f5fc0), LL(0x8d8d0e8d1c830791), LL(0x3d3df43df5c97ac8),
    LL(0x97976697ccf1335b), LL(0x0000000000000000), LL(0xcfcf1bcf36d483f9), LL(0x2b2bac2b4587566e),
    LL(0x7676c57697b3ece1), LL(0x8282328264b019e6), LL(0xd6d67fd6fea9b128), LL(0x1b1b6c1bd87736c3),
    LL(0xb5b5eeb5c15b7774), LL(0xafaf86af112943be), LL(0x6a6ab56a77dfd41d), LL(0x50505d50ba0da0ea),
    LL(0x45450945124c8a57), LL(0xf3f3ebf3cb18fb38), LL(0x3030c0309df060ad), LL(0xefef9bef2b74c3c4),
    LL(0x3f3ffc3fe5c37eda), LL(0x55554955921caac7), LL(0xa2a2b2a2791059db), LL(0xeaea8fea0365c9e9),
    LL(0x656589650fecca6a), LL(0xbabad2bab9686903), LL(0x2f2fbc2f65935e4a), LL(0xc0c027c04ee79d8e),
    LL(0xdede5fdebe81a160), LL(0x1c1c701ce06c38fc), LL(0xfdfdd3fdbb2ee746), LL(0x4d4d294d52649a1f),
    LL(0x92927292e4e03976), LL(0x7575c9758fbceafa), LL(0x06061806301e0c36), LL(0x8a8a128a249809ae),
    LL(0xb2b2f2b2f940794b), LL(0xe6e6bfe66359d185), LL(0x0e0e380e70361c7e), LL(0x1f1f7c1ff8633ee7),
    LL(0x6262956237f7c455), LL(0xd4d477d4eea3b53a), LL(0xa8a89aa829324d81), LL(0x96966296c4f43152),
    LL(0xf9f9c3f99b3aef62), LL(0xc5c533c566f697a3), LL(0x2525942535b14a10), LL(0x59597959f220b2ab),
    LL(0x84842a8454ae15d0), LL(0x7272d572b7a7e4c5), LL(0x3939e439d5dd72ec), LL(0x4c4c2d4c5a619816),
    LL(0x5e5e655eca3bbc94), LL(0x7878fd78e785f09f), LL(0x3838e038ddd870e5), LL(0x8c8c0a8c14860598),
    LL(0xd1d163d1c6b2bf17), LL(0xa5a5aea5410b57e4), LL(0xe2e2afe2434dd9a1), LL(0x616199612ff8c24e),
    LL(0xb3b3f6b3f1457b42), LL(0x2121842115a54234), LL(0x9c9c4a9c94d62508), LL(0x1e1e781ef0663cee),
    LL(0x4343114322528661), LL(0xc7c73bc776fc93b1), LL(0xfcfcd7fcb32be54f), LL(0x0404100420140824),
    LL(0x51515951b208a2e3), LL(0x99995e99bcc72f25), LL(0x6d6da96d4fc4da22), LL(0x0d0d340d68391a65),
    LL(0xfafacffa8335e979), LL(0xdfdf5bdfb684a369), LL(0x7e7ee57ed79bfca9), LL(0x242490243db44819),
    LL(0x3b3bec3bc5d776fe), LL(0xabab96ab313d4b9a), LL(0xcece1fce3ed181f0), LL(0x1111441188552299),
    LL(0x8f8f068f0c890383), LL(0x4e4e254e4a6b9c04), LL(0xb7b7e6b7d1517366), LL(0xebeb8beb0b60cbe0),
    LL(0x3c3cf03cfdcc78c1), LL(0x81813e817cbf1ffd), LL(0x94946a94d4fe3540), LL(0xf7f7fbf7eb0cf31c),
    LL(0xb9b9deb9a1676f18), LL(0x13134c13985f268b), LL(0x2c2cb02c7d9c5851), LL(0xd3d36bd3d6b8bb05),
    LL(0xe7e7bbe76b5cd38c), LL(0x6e6ea56e57cbdc39), LL(0xc4c437c46ef395aa), LL(0x03030c03180f061b),
    LL(0x565645568a13acdc), LL(0x44440d441a49885e), LL(0x7f7fe17fdf9efea0), LL(0xa9a99ea921374f88),
    LL(0x2a2aa82a4d825467), LL(0xbbbbd6bbb16d6b0a), LL(0xc1c123c146e29f87), LL(0x53535153a202a6f1),
    LL(0xdcdc57dcae8ba572), LL(0x0b0b2c0b58271653), LL(0x9d9d4e9d9cd32701), LL(0x6c6cad6c47c1d82b),
    LL(0x3131c43195f562a4), LL(0x7474cd7487b9e8f3), LL(0xf6f6fff6e309f115), LL(0x464605460a438c4c),
    LL(0xacac8aac092645a5), LL(0x89891e893c970fb5), LL(0x14145014a04428b4), LL(0xe1e1a3e15b42dfba),
    LL(0x16165816b04e2ca6), LL(0x3a3ae83acdd274f7), LL(0x6969b9696fd0d206), LL(0x09092409482d1241),
    LL(0x7070dd70a7ade0d7), LL(0xb6b6e2b6d954716f), LL(0xd0d067d0ceb7bd1e), LL(0xeded93ed3b7ec7d6),
    LL(0xcccc17cc2edb85e2), LL(0x424215422a578468), LL(0x98985a98b4c22d2c), LL(0xa4a4aaa4490e55ed),
    LL(0x2828a0285d885075), LL(0x5c5c6d5cda31b886), LL(0xf8f8c7f8933fed6b), LL(0x8686228644a411c2),
};

static const u64 C1[256] = {
    LL(0xd818186018c07830), LL(0x2623238c2305af46), LL(0xb8c6c63fc67ef991), LL(0xfbe8e887e8136fcd),
    LL(0xcb878726874ca113), LL(0x11b8b8dab8a9626d), LL(0x0901010401080502), LL(0x0d4f4f214f426e9e),
    LL(0x9b3636d836adee6c), LL(0xffa6a6a2a6590451), LL(0x0cd2d26fd2debdb9), LL(0x0ef5f5f3f5fb06f7),
    LL(0x967979f979ef80f2), LL(0x306f6fa16f5fcede), LL(0x6d91917e91fcef3f), LL(0xf852525552aa07a4),
    LL(0x4760609d6027fdc0), LL(0x35bcbccabc897665), LL(0x379b9b569baccd2b), LL(0x8a8e8e028e048c01),
    LL(0xd2a3a3b6a371155b), LL(0x6c0c0c300c603c18), LL(0x847b7bf17bff8af6), LL(0x803535d435b5e16a),
    LL(0xf51d1d741de8693a), LL(0xb3e0e0a7e05347dd), LL(0x21d7d77bd7f6acb3), LL(0x9cc2c22fc25eed99),
    LL(0x432e2eb82e6d965c), LL(0x294b4b314b627a96), LL(0x5dfefedffea321e1), LL(0xd5575741578216ae),
    LL(0xbd15155415a8412a), LL(0xe87777c1779fb6ee), LL(0x923737dc37a5eb6e), LL(0x9ee5e5b3e57b56d7),
    LL(0x139f9f469f8cd923), LL(0x23f0f0e7f0d317fd), LL(0x204a4a354a6a7f94), LL(0x44dada4fda9e95a9),
    LL(0xa258587d58fa25b0), LL(0xcfc9c903c906ca8f), LL(0x7c2929a429558d52), LL(0x5a0a0a280a502214),
    LL(0x50b1b1feb1e14f7f), LL(0xc9a0a0baa0691a5d), LL(0x146b6bb16b7fdad6), LL(0xd985852e855cab17),
    LL(0x3cbdbdcebd817367), LL(0x8f5d5d695dd234ba), LL(0x9010104010805020), LL(0x07f4f4f7f4f303f5),
    LL(0xddcbcb0bcb16c08b), LL(0xd33e3ef83eedc67c), LL(0x2d0505140528110a), LL(0x78676781671fe6ce),
    LL(0x97e4e4b7e47353d5), LL(0x0227279c2725bb4e), LL(0x7341411941325882), LL(0xa78b8b168b2c9d0b),
    LL(0xf6a7a7a6a7510153), LL(0xb27d7de97dcf94fa), LL(0x4995956e95dcfb37), LL(0x56d8d847d88e9fad),
    LL(0x70fbfbcbfb8b30eb), LL(0xcdeeee9fee2371c1), LL(0xbb7c7ced7cc791f8), LL(0x716666856617e3cc),
    LL(0x7bdddd53dda68ea7), LL(0xaf17175c17b84b2e), LL(0x454747014702468e), LL(0x1a9e9e429e84dc21),
    LL(0xd4caca0fca1ec589), LL(0x582d2db42d75995a), LL(0x2ebfbfc6bf917963), LL(0x3f07071c07381b0e),
    LL(0xacadad8ead012347), LL(0xb05a5a755aea2fb4), LL(0xef838336836cb51b), LL(0xb63333cc3385ff66),
    LL(0x5c636391633ff2c6), LL(0x1202020802100a04), LL(0x93aaaa92aa393849), LL(0xde7171d971afa8e2),
    LL(0xc6c8c807c80ecf8d), LL(0xd119196419c87d32), LL(0x3b49493949727092), LL(0x5fd9d943d9869aaf),
    LL(0x31f2f2eff2c31df9), LL(0xa8e3e3abe34b48db), LL(0xb95b5b715be22ab6), LL(0xbc88881a8834920d),
    LL(0x3e9a9a529aa4c829), LL(0x0b262698262dbe4c), LL(0xbf3232c8328dfa64), LL(0x59b0b0fab0e94a7d),
    LL(0xf2e9e983e91b6acf), LL(0x770f0f3c0f78331e), LL(0x33d5d573d5e6a6b7), LL(0xf480803a8074ba1d),
    LL(0x27bebec2be997c61), LL(0xebcdcd13cd26de87), LL(0x893434d034bde468), LL(0x3248483d487a7590),
    LL(0x54ffffdbffab24e3), LL(0x8d7a7af57af78ff4), LL(0x6490907a90f4ea3d), LL(0x9d5f5f615fc23ebe),
    LL(0x3d202080201da040), LL(0x0f6868bd6867d5d0), LL(0xca1a1a681ad07234), LL(0xb7aeae82ae192c41),
    LL(0x7db4b4eab4c95e75), LL(0xce54544d549a19a8), LL(0x7f93937693ece53b), LL(0x2f222288220daa44),
    LL(0x6364648d6407e9c8), LL(0x2af1f1e3f1db12ff), LL(0xcc7373d173bfa2e6), LL(0x8212124812905a24),
    LL(0x7a40401d403a5d80), LL(0x4808082008402810), LL(0x95c3c32bc356e89b), LL(0xdfecec97ec337bc5),
    LL(0x4ddbdb4bdb9690ab), LL(0xc0a1a1bea1611f5f), LL(0x918d8d0e8d1c8307), LL(0xc83d3df43df5c97a),
    LL(0x5b97976697ccf133), LL(0x0000000000000000), LL(0xf9cfcf1bcf36d483), LL(0x6e2b2bac2b458756),
    LL(0xe17676c57697b3ec), LL(0xe68282328264b019), LL(0x28d6d67fd6fea9b1), LL(0xc31b1b6c1bd87736),
    LL(0x74b5b5eeb5c15b77), LL(0xbeafaf86af112943), LL(0x1d6a6ab56a77dfd4), LL(0xea50505d50ba0da0),
    LL(0x5745450945124c8a), LL(0x38f3f3ebf3cb18fb), LL(0xad3030c0309df060), LL(0xc4efef9bef2b74c3),
    LL(0xda3f3ffc3fe5c37e), LL(0xc755554955921caa), LL(0xdba2a2b2a2791059), LL(0xe9eaea8fea0365c9),
    LL(0x6a656589650fecca), LL(0x03babad2bab96869), LL(0x4a2f2fbc2f65935e), LL(0x8ec0c027c04ee79d),
    LL(0x60dede5fdebe81a1), LL(0xfc1c1c701ce06c38), LL(0x46fdfdd3fdbb2ee7), LL(0x1f4d4d294d52649a),
    LL(0x7692927292e4e039), LL(0xfa7575c9758fbcea), LL(0x3606061806301e0c), LL(0xae8a8a128a249809),
    LL(0x4bb2b2f2b2f94079), LL(0x85e6e6bfe66359d1), LL(0x7e0e0e380e70361c), LL(0xe71f1f7c1ff8633e),
    LL(0x556262956237f7c4), LL(0x3ad4d477d4eea3b5), LL(0x81a8a89aa829324d), LL(0x5296966296c4f431),
    LL(0x62f9f9c3f99b3aef), LL(0xa3c5c533c566f697), LL(0x102525942535b14a), LL(0xab59597959f220b2),
    LL(0xd084842a8454ae15), LL(0xc57272d572b7a7e4), LL(0xec3939e439d5dd72), LL(0x164c4c2d4c5a6198),
    LL(0x945e5e655eca3bbc), LL(0x9f7878fd78e785f0), LL(0xe53838e038ddd870), LL(0x988c8c0a8c148605),
    LL(0x17d1d163d1c6b2bf), LL(0xe4a5a5aea5410b57), LL(0xa1e2e2afe2434dd9), LL(0x4e616199612ff8c2),
    LL(0x42b3b3f6b3f1457b), LL(0x342121842115a542), LL(0x089c9c4a9c94d625), LL(0xee1e1e781ef0663c),
    LL(0x6143431143225286), LL(0xb1c7c73bc776fc93), LL(0x4ffcfcd7fcb32be5), LL(0x2404041004201408),
    LL(0xe351515951b208a2), LL(0x2599995e99bcc72f), LL(0x226d6da96d4fc4da), LL(0x650d0d340d68391a),
    LL(0x79fafacffa8335e9), LL(0x69dfdf5bdfb684a3), LL(0xa97e7ee57ed79bfc), LL(0x19242490243db448),
    LL(0xfe3b3bec3bc5d776), LL(0x9aabab96ab313d4b), LL(0xf0cece1fce3ed181), LL(0x9911114411885522),
    LL(0x838f8f068f0c8903), LL(0x044e4e254e4a6b9c), LL(0x66b7b7e6b7d15173), LL(0xe0ebeb8beb0b60cb),
    LL(0xc13c3cf03cfdcc78), LL(0xfd81813e817cbf1f), LL(0x4094946a94d4fe35), LL(0x1cf7f7fbf7eb0cf3),
    LL(0x18b9b9deb9a1676f), LL(0x8b13134c13985f26), LL(0x512c2cb02c7d9c58), LL(0x05d3d36bd3d6b8bb),
    LL(0x8ce7e7bbe76b5cd3), LL(0x396e6ea56e57cbdc), LL(0xaac4c437c46ef395), LL(0x1b03030c03180f06),
    LL(0xdc565645568a13ac), LL(0x5e44440d441a4988), LL(0xa07f7fe17fdf9efe), LL(0x88a9a99ea921374f),
    LL(0x672a2aa82a4d8254), LL(0x0abbbbd6bbb16d6b), LL(0x87c1c123c146e29f), LL(0xf153535153a202a6),
    LL(0x72dcdc57dcae8ba5), LL(0x530b0b2c0b582716), LL(0x019d9d4e9d9cd327), LL(0x2b6c6cad6c47c1d8),
    LL(0xa43131c43195f562), LL(0xf37474cd7487b9e8), LL(0x15f6f6fff6e309f1), LL(0x4c464605460a438c),
    LL(0xa5acac8aac092645), LL(0xb589891e893c970f), LL(0xb414145014a04428), LL(0xbae1e1a3e15b42df),
    LL(0xa616165816b04e2c), LL(0xf73a3ae83acdd274), LL(0x066969b9696fd0d2), LL(0x4109092409482d12),
    LL(0xd77070dd70a7ade0), LL(0x6fb6b6e2b6d95471), LL(0x1ed0d067d0ceb7bd), LL(0xd6eded93ed3b7ec7),
    LL(0xe2cccc17cc2edb85), LL(0x68424215422a5784), LL(0x2c98985a98b4c22d), LL(0xeda4a4aaa4490e55),
    LL(0x752828a0285d8850), LL(0x865c5c6d5cda31b8), LL(0x6bf8f8c7f8933fed), LL(0xc28686228644a411),
};

static const u64 C2[256] = {
    LL(0x30d818186018c078), LL(0x462623238c2305af), LL(0x91b8c6c63fc67ef9), LL(0xcdfbe8e887e8136f),
    LL(0x13cb878726874ca1), LL(0x6d11b8b8dab8a962), LL(0x0209010104010805), LL(0x9e0d4f4f214f426e),
    LL(0x6c9b3636d836adee), LL(0x51ffa6a6a2a65904), LL(0xb90cd2d26fd2debd), LL(0xf70ef5f5f3f5fb06),
    LL(0xf2967979f979ef80), LL(0xde306f6fa16f5fce), LL(0x3f6d91917e91fcef), LL(0xa4f852525552aa07),
    LL(0xc04760609d6027fd), LL(0x6535bcbccabc8976), LL(0x2b379b9b569baccd), LL(0x018a8e8e028e048c),
    LL(0x5bd2a3a3b6a37115), LL(0x186c0c0c300c603c), LL(0xf6847b7bf17bff8a), LL(0x6a803535d435b5e1),
    LL(0x3af51d1d741de869), LL(0xddb3e0e0a7e05347), LL(0xb321d7d77bd7f6ac), LL(0x999cc2c22fc25eed),
    LL(0x5c432e2eb82e6d96), LL(0x96294b4b314b627a), LL(0xe15dfefedffea321), LL(0xaed5575741578216),
    LL(0x2abd15155415a841), LL(0xeee87777c1779fb6), LL(0x6e923737dc37a5eb), LL(0xd79ee5e5b3e57b56),
    LL(0x23139f9f469f8cd9), LL(0xfd23f0f0e7f0d317), LL(0x94204a4a354a6a7f), LL(0xa944dada4fda9e95),
    LL(0xb0a258587d58fa25), LL(0x8fcfc9c903c906ca), LL(0x527c2929a429558d), LL(0x145a0a0a280a5022),
    LL(0x7f50b1b1feb1e14f), LL(0x5dc9a0a0baa0691a), LL(0xd6146b6bb16b7fda), LL(0x17d985852e855cab),
    LL(0x673cbdbdcebd8173), LL(0xba8f5d5d695dd234), LL(0x2090101040108050), LL(0xf507f4f4f7f4f303),
    LL(0x8bddcbcb0bcb16c0), LL(0x7cd33e3ef83eedc6), LL(0x0a2d050514052811), LL(0xce78676781671fe6),
    LL(0xd597e4e4b7e47353), LL(0x4e0227279c2725bb), LL(0x8273414119413258), LL(0x0ba78b8b168b2c9d),
    LL(0x53f6a7a7a6a75101), LL(0xfab27d7de97dcf94), LL(0x374995956e95dcfb), LL(0xad56d8d847d88e9f),
    LL(0xeb70fbfbcbfb8b30), LL(0xc1cdeeee9fee2371), LL(0xf8bb7c7ced7cc791), LL(0xcc716666856617e3),
    LL(0xa77bdddd53dda68e), LL(0x2eaf17175c17b84b), LL(0x8e45474701470246), LL(0x211a9e9e429e84dc),
    LL(0x89d4caca0fca1ec5), LL(0x5a582d2db42d7599), LL(0x632ebfbfc6bf9179), LL(0x0e3f07071c07381b),
    LL(0x47acadad8ead0123), LL(0xb4b05a5a755aea2f), LL(0x1bef838336836cb5), LL(0x66b63333cc3385ff),
    LL(0xc65c636391633ff2), LL(0x041202020802100a), LL(0x4993aaaa92aa3938), LL(0xe2de7171d971afa8),
    LL(0x8dc6c8c807c80ecf), LL(0x32d119196419c87d), LL(0x923b494939497270), LL(0xaf5fd9d943d9869a),
    LL(0xf931f2f2eff2c31d), LL(0xdba8e3e3abe34b48), LL(0xb6b95b5b715be22a), LL(0x0dbc88881a883492),
    LL(0x293e9a9a529aa4c8), LL(0x4c0b262698262dbe), LL(0x64bf3232c8328dfa), LL(0x7d59b0b0fab0e94a),
    LL(0xcff2e9e983e91b6a), LL(0x1e770f0f3c0f7833), LL(0xb733d5d573d5e6a6), LL(0x1df480803a8074ba),
    LL(0x6127bebec2be997c), LL(0x87ebcdcd13cd26de), LL(0x68893434d034bde4), LL(0x903248483d487a75),
    LL(0xe354ffffdbffab24), LL(0xf48d7a7af57af78f), LL(0x3d6490907a90f4ea), LL(0xbe9d5f5f615fc23e),
    LL(0x403d202080201da0), LL(0xd00f6868bd6867d5), LL(0x34ca1a1a681ad072), LL(0x41b7aeae82ae192c),
    LL(0x757db4b4eab4c95e), LL(0xa8ce54544d549a19), LL(0x3b7f93937693ece5), LL(0x442f222288220daa),
    LL(0xc86364648d6407e9), LL(0xff2af1f1e3f1db12), LL(0xe6cc7373d173bfa2), LL(0x248212124812905a),
    LL(0x807a40401d403a5d), LL(0x1048080820084028), LL(0x9b95c3c32bc356e8), LL(0xc5dfecec97ec337b),
    LL(0xab4ddbdb4bdb9690), LL(0x5fc0a1a1bea1611f), LL(0x07918d8d0e8d1c83), LL(0x7ac83d3df43df5c9),
    LL(0x335b97976697ccf1), LL(0x0000000000000000), LL(0x83f9cfcf1bcf36d4), LL(0x566e2b2bac2b4587),
    LL(0xece17676c57697b3), LL(0x19e68282328264b0), LL(0xb128d6d67fd6fea9), LL(0x36c31b1b6c1bd877),
    LL(0x7774b5b5eeb5c15b), LL(0x43beafaf86af1129), LL(0xd41d6a6ab56a77df), LL(0xa0ea50505d50ba0d),
    LL(0x8a5745450945124c), LL(0xfb38f3f3ebf3cb18), LL(0x60ad3030c0309df0), LL(0xc3c4efef9bef2b74),
    LL(0x7eda3f3ffc3fe5c3), LL(0xaac755554955921c), LL(0x59dba2a2b2a27910), LL(0xc9e9eaea8fea0365),
    LL(0xca6a656589650fec), LL(0x6903babad2bab968), LL(0x5e4a2f2fbc2f6593), LL(0x9d8ec0c027c04ee7),
    LL(0xa160dede5fdebe81), LL(0x38fc1c1c701ce06c), LL(0xe746fdfdd3fdbb2e), LL(0x9a1f4d4d294d5264),
    LL(0x397692927292e4e0), LL(0xeafa7575c9758fbc), LL(0x0c3606061806301e), LL(0x09ae8a8a128a2498),
    LL(0x794bb2b2f2b2f940), LL(0xd185e6e6bfe66359), LL(0x1c7e0e0e380e7036), LL(0x3ee71f1f7c1ff863),
    LL(0xc4556262956237f7), LL(0xb53ad4d477d4eea3), LL(0x4d81a8a89aa82932), LL(0x315296966296c4f4),
    LL(0xef62f9f9c3f99b3a), LL(0x97a3c5c533c566f6), LL(0x4a102525942535b1), LL(0xb2ab59597959f220),
    LL(0x15d084842a8454ae), LL(0xe4c57272d572b7a7), LL(0x72ec3939e439d5dd), LL(0x98164c4c2d4c5a61),
    LL(0xbc945e5e655eca3b), LL(0xf09f7878fd78e785), LL(0x70e53838e038ddd8), LL(0x05988c8c0a8c1486),
    LL(0xbf17d1d163d1c6b2), LL(0x57e4a5a5aea5410b), LL(0xd9a1e2e2afe2434d), LL(0xc24e616199612ff8),
    LL(0x7b42b3b3f6b3f145), LL(0x42342121842115a5), LL(0x25089c9c4a9c94d6), LL(0x3cee1e1e781ef066),
    LL(0x8661434311432252), LL(0x93b1c7c73bc776fc), LL(0xe54ffcfcd7fcb32b), LL(0x0824040410042014),
    LL(0xa2e351515951b208), LL(0x2f2599995e99bcc7), LL(0xda226d6da96d4fc4), LL(0x1a650d0d340d6839),
    LL(0xe979fafacffa8335), LL(0xa369dfdf5bdfb684), LL(0xfca97e7ee57ed79b), LL(0x4819242490243db4),
    LL(0x76fe3b3bec3bc5d7), LL(0x4b9aabab96ab313d), LL(0x81f0cece1fce3ed1), LL(0x2299111144118855),
    LL(0x03838f8f068f0c89), LL(0x9c044e4e254e4a6b), LL(0x7366b7b7e6b7d151), LL(0xcbe0ebeb8beb0b60),
    LL(0x78c13c3cf03cfdcc), LL(0x1ffd81813e817cbf), LL(0x354094946a94d4fe), LL(0xf31cf7f7fbf7eb0c),
    LL(0x6f18b9b9deb9a167), LL(0x268b13134c13985f), LL(0x58512c2cb02c7d9c), LL(0xbb05d3d36bd3d6b8),
    LL(0xd38ce7e7bbe76b5c), LL(0xdc396e6ea56e57cb), LL(0x95aac4c437c46ef3), LL(0x061b03030c03180f),
    LL(0xacdc565645568a13), LL(0x885e44440d441a49), LL(0xfea07f7fe17fdf9e), LL(0x4f88a9a99ea92137),
    LL(0x54672a2aa82a4d82), LL(0x6b0abbbbd6bbb16d), LL(0x9f87c1c123c146e2), LL(0xa6f153535153a202),
    LL(0xa572dcdc57dcae8b), LL(0x16530b0b2c0b5827), LL(0x27019d9d4e9d9cd3), LL(0xd82b6c6cad6c47c1),
    LL(0x62a43131c43195f5), LL(0xe8f37474cd7487b9), LL(0xf115f6f6fff6e309), LL(0x8c4c464605460a43),
    LL(0x45a5acac8aac0926), LL(0x0fb589891e893c97), LL(0x28b414145014a044), LL(0xdfbae1e1a3e15b42),
    LL(0x2ca616165816b04e), LL(0x74f73a3ae83acdd2), LL(0xd2066969b9696fd0), LL(0x124109092409482d),
    LL(0xe0d77070dd70a7ad), LL(0x716fb6b6e2b6d954), LL(0xbd1ed0d067d0ceb7), LL(0xc7d6eded93ed3b7e),
    LL(0x85e2cccc17cc2edb), LL(0x8468424215422a57), LL(0x2d2c98985a98b4c2), LL(0x55eda4a4aaa4490e),
    LL(0x50752828a0285d88), LL(0xb8865c5c6d5cda31), LL(0xed6bf8f8c7f8933f), LL(0x11c28686228644a4),
};

static const u64 C3[256] = {
    LL(0x7830d818186018c0), LL(0xaf462623238c2305), LL(0xf991b8c6c63fc67e), LL(0x6fcdfbe8e887e813),
    LL(0xa113cb878726874c), LL(0x626d11b8b8dab8a9), LL(0x0502090101040108), LL(0x6e9e0d4f4f214f42),
    LL(0xee6c9b3636d836ad), LL(0x0451ffa6a6a2a659), LL(0xbdb90cd2d26fd2de), LL(0x06f70ef5f5f3f5fb),
    LL(0x80f2967979f979ef), LL(0xcede306f6fa16f5f), LL(0xef3f6d91917e91fc), LL(0x07a4f852525552aa),
    LL(0xfdc04760609d6027), LL(0x766535bcbccabc89), LL(0xcd2b379b9b569bac), LL(0x8c018a8e8e028e04),
    LL(0x155bd2a3a3b6a371), LL(0x3c186c0c0c300c60), LL(0x8af6847b7bf17bff), LL(0xe16a803535d435b5),
    LL(0x693af51d1d741de8), LL(0x47ddb3e0e0a7e053), LL(0xacb321d7d77bd7f6), LL(0xed999cc2c22fc25e),
    LL(0x965c432e2eb82e6d), LL(0x7a96294b4b314b62), LL(0x21e15dfefedffea3), LL(0x16aed55757415782),
    LL(0x412abd15155415a8), LL(0xb6eee87777c1779f), LL(0xeb6e923737dc37a5), LL(0x56d79ee5e5b3e57b),
    LL(0xd923139f9f469f8c), LL(0x17fd23f0f0e7f0d3), LL(0x7f94204a4a354a6a), LL(0x95a944dada4fda9e),
    LL(0x25b0a258587d58fa), LL(0xca8fcfc9c903c906), LL(0x8d527c2929a42955), LL(0x22145a0a0a280a50),
    LL(0x4f7f50b1b1feb1e1), LL(0x1a5dc9a0a0baa069), LL(0xdad6146b6bb16b7f), LL(0xab17d985852e855c),
    LL(0x73673cbdbdcebd81), LL(0x34ba8f5d5d695dd2), LL(0x5020901010401080), LL(0x03f507f4f4f7f4f3),
    LL(0xc08bddcbcb0bcb16), LL(0xc67cd33e3ef83eed), LL(0x110a2d0505140528), LL(0xe6ce78676781671f),
    LL(0x53d597e4e4b7e473), LL(0xbb4e0227279c2725), LL(0x5882734141194132), LL(0x9d0ba78b8b168b2c),
    LL(0x0153f6a7a7a6a751), LL(0x94fab27d7de97dcf), LL(0xfb374995956e95dc), LL(0x9fad56d8d847d88e),
    LL(0x30eb70fbfbcbfb8b), LL(0x71c1cdeeee9fee23), LL(0x91f8bb7c7ced7cc7), LL(0xe3cc716666856617),
    LL(0x8ea77bdddd53dda6), LL(0x4b2eaf17175c17b8), LL(0x468e454747014702), LL(0xdc211a9e9e429e84),
    LL(0xc589d4caca0fca1e), LL(0x995a582d2db42d75), LL(0x79632ebfbfc6bf91), LL(0x1b0e3f07071c0738),
    LL(0x2347acadad8ead01), LL(0x2fb4b05a5a755aea), LL(0xb51bef838336836c), LL(0xff66b63333cc3385),
    LL(0xf2c65c636391633f), LL(0x0a04120202080210), LL(0x384993aaaa92aa39), LL(0xa8e2de7171d971af),
    LL(0xcf8dc6c8c807c80e), LL(0x7d32d119196419c8), LL(0x70923b4949394972), LL(0x9aaf5fd9d943d986),
    LL(0x1df931f2f2eff2c3), LL(0x48dba8e3e3abe34b), LL(0x2ab6b95b5b715be2), LL(0x920dbc88881a8834),
    LL(0xc8293e9a9a529aa4), LL(0xbe4c0b262698262d), LL(0xfa64bf3232c8328d), LL(0x4a7d59b0b0fab0e9),
    LL(0x6acff2e9e983e91b), LL(0x331e770f0f3c0f78), LL(0xa6b733d5d573d5e6), LL(0xba1df480803a8074),
    LL(0x7c6127bebec2be99), LL(0xde87ebcdcd13cd26), LL(0xe468893434d034bd), LL(0x75903248483d487a),
    LL(0x24e354ffffdbffab), LL(0x8ff48d7a7af57af7), LL(0xea3d6490907a90f4), LL(0x3ebe9d5f5f615fc2),
    LL(0xa0403d202080201d), LL(0xd5d00f6868bd6867), LL(0x7234ca1a1a681ad0), LL(0x2c41b7aeae82ae19),
    LL(0x5e757db4b4eab4c9), LL(0x19a8ce54544d549a), LL(0xe53b7f93937693ec), LL(0xaa442f222288220d),
    LL(0xe9c86364648d6407), LL(0x12ff2af1f1e3f1db), LL(0xa2e6cc7373d173bf), LL(0x5a24821212481290),
    LL(0x5d807a40401d403a), LL(0x2810480808200840), LL(0xe89b95c3c32bc356), LL(0x7bc5dfecec97ec33),
    LL(0x90ab4ddbdb4bdb96), LL(0x1f5fc0a1a1bea161), LL(0x8307918d8d0e8d1c), LL(0xc97ac83d3df43df5),
    LL(0xf1335b97976697cc), LL(0x0000000000000000), LL(0xd483f9cfcf1bcf36), LL(0x87566e2b2bac2b45),
    LL(0xb3ece17676c57697), LL(0xb019e68282328264), LL(0xa9b128d6d67fd6fe), LL(0x7736c31b1b6c1bd8),
    LL(0x5b7774b5b5eeb5c1), LL(0x2943beafaf86af11), LL(0xdfd41d6a6ab56a77), LL(0x0da0ea50505d50ba),
    LL(0x4c8a574545094512), LL(0x18fb38f3f3ebf3cb), LL(0xf060ad3030c0309d), LL(0x74c3c4efef9bef2b),
    LL(0xc37eda3f3ffc3fe5), LL(0x1caac75555495592), LL(0x1059dba2a2b2a279), LL(0x65c9e9eaea8fea03),
    LL(0xecca6a656589650f), LL(0x686903babad2bab9), LL(0x935e4a2f2fbc2f65), LL(0xe79d8ec0c027c04e),
    LL(0x81a160dede5fdebe), LL(0x6c38fc1c1c701ce0), LL(0x2ee746fdfdd3fdbb), LL(0x649a1f4d4d294d52),
    LL(0xe0397692927292e4), LL(0xbceafa7575c9758f), LL(0x1e0c360606180630), LL(0x9809ae8a8a128a24),
    LL(0x40794bb2b2f2b2f9), LL(0x59d185e6e6bfe663), LL(0x361c7e0e0e380e70), LL(0x633ee71f1f7c1ff8),
    LL(0xf7c4556262956237), LL(0xa3b53ad4d477d4ee), LL(0x324d81a8a89aa829), LL(0xf4315296966296c4),
    LL(0x3aef62f9f9c3f99b), LL(0xf697a3c5c533c566), LL(0xb14a102525942535), LL(0x20b2ab59597959f2),
    LL(0xae15d084842a8454), LL(0xa7e4c57272d572b7), LL(0xdd72ec3939e439d5), LL(0x6198164c4c2d4c5a),
    LL(0x3bbc945e5e655eca), LL(0x85f09f7878fd78e7), LL(0xd870e53838e038dd), LL(0x8605988c8c0a8c14),
    LL(0xb2bf17d1d163d1c6), LL(0x0b57e4a5a5aea541), LL(0x4dd9a1e2e2afe243), LL(0xf8c24e616199612f),
    LL(0x457b42b3b3f6b3f1), LL(0xa542342121842115), LL(0xd625089c9c4a9c94), LL(0x663cee1e1e781ef0),
    LL(0x5286614343114322), LL(0xfc93b1c7c73bc776), LL(0x2be54ffcfcd7fcb3), LL(0x1408240404100420),
    LL(0x08a2e351515951b2), LL(0xc72f2599995e99bc), LL(0xc4da226d6da96d4f), LL(0x391a650d0d340d68),
    LL(0x35e979fafacffa83), LL(0x84a369dfdf5bdfb6), LL(0x9bfca97e7ee57ed7), LL(0xb44819242490243d),
    LL(0xd776fe3b3bec3bc5), LL(0x3d4b9aabab96ab31), LL(0xd181f0cece1fce3e), LL(0x5522991111441188),
    LL(0x8903838f8f068f0c), LL(0x6b9c044e4e254e4a), LL(0x517366b7b7e6b7d1), LL(0x60cbe0ebeb8beb0b),
    LL(0xcc78c13c3cf03cfd), LL(0xbf1ffd81813e817c), LL(0xfe354094946a94d4), LL(0x0cf31cf7f7fbf7eb),
    LL(0x676f18b9b9deb9a1), LL(0x5f268b13134c1398), LL(0x9c58512c2cb02c7d), LL(0xb8bb05d3d36bd3d6),
    LL(0x5cd38ce7e7bbe76b), LL(0xcbdc396e6ea56e57), LL(0xf395aac4c437c46e), LL(0x0f061b03030c0318),
    LL(0x13acdc565645568a), LL(0x49885e44440d441a), LL(0x9efea07f7fe17fdf), LL(0x374f88a9a99ea921),
    LL(0x8254672a2aa82a4d), LL(0x6d6b0abbbbd6bbb1), LL(0xe29f87c1c123c146), LL(0x02a6f153535153a2),
    LL(0x8ba572dcdc57dcae), LL(0x2716530b0b2c0b58), LL(0xd327019d9d4e9d9c), LL(0xc1d82b6c6cad6c47),
    LL(0xf562a43131c43195), LL(0xb9e8f37474cd7487), LL(0x09f115f6f6fff6e3), LL(0x438c4c464605460a),
    LL(0x2645a5acac8aac09), LL(0x970fb589891e893c), LL(0x4428b414145014a0), LL(0x42dfbae1e1a3e15b),
    LL(0x4e2ca616165816b0), LL(0xd274f73a3ae83acd), LL(0xd0d2066969b9696f), LL(0x2d12410909240948),
    LL(0xade0d77070dd70a7), LL(0x54716fb6b6e2b6d9), LL(0xb7bd1ed0d067d0ce), LL(0x7ec7d6eded93ed3b),
    LL(0xdb85e2cccc17cc2e), LL(0x578468424215422a), LL(0xc22d2c98985a98b4), LL(0x0e55eda4a4aaa449),
    LL(0x8850752828a0285d), LL(0x31b8865c5c6d5cda), LL(0x3fed6bf8f8c7f893), LL(0xa411c28686228644),
};

static const u64 C4[256] = {
    LL(0xc07830d818186018), LL(0x05af462623238c23), LL(0x7ef991b8c6c63fc6), LL(0x136fcdfbe8e887e8),
    LL(0x4ca113cb87872687), LL(0xa9626d11b8b8dab8), LL(0x0805020901010401), LL(0x426e9e0d4f4f214f),
    LL(0xadee6c9b3636d836), LL(0x590451ffa6a6a2a6), LL(0xdebdb90cd2d26fd2), LL(0xfb06f70ef5f5f3f5),
    LL(0xef80f2967979f979), LL(0x5fcede306f6fa16f), LL(0xfcef3f6d91917e91), LL(0xaa07a4f852525552),
    LL(0x27fdc04760609d60), LL(0x89766535bcbccabc), LL(0xaccd2b379b9b569b), LL(0x048c018a8e8e028e),
    LL(0x71155bd2a3a3b6a3), LL(0x603c186c0c0c300c), LL(0xff8af6847b7bf17b), LL(0xb5e16a803535d435),
    LL(0xe8693af51d1d741d), LL(0x5347ddb3e0e0a7e0), LL(0xf6acb321d7d77bd7), LL(0x5eed999cc2c22fc2),
    LL(0x6d965c432e2eb82e), LL(0x627a96294b4b314b), LL(0xa321e15dfefedffe), LL(0x8216aed557574157),
    LL(0xa8412abd15155415), LL(0x9fb6eee87777c177), LL(0xa5eb6e923737dc37), LL(0x7b56d79ee5e5b3e5),
    LL(0x8cd923139f9f469f), LL(0xd317fd23f0f0e7f0), LL(0x6a7f94204a4a354a), LL(0x9e95a944dada4fda),
    LL(0xfa25b0a258587d58), LL(0x06ca8fcfc9c903c9), LL(0x558d527c2929a429), LL(0x5022145a0a0a280a),
    LL(0xe14f7f50b1b1feb1), LL(0x691a5dc9a0a0baa0), LL(0x7fdad6146b6bb16b), LL(0x5cab17d985852e85),
    LL(0x8173673cbdbdcebd), LL(0xd234ba8f5d5d695d), LL(0x8050209010104010), LL(0xf303f507f4f4f7f4),
    LL(0x16c08bddcbcb0bcb), LL(0xedc67cd33e3ef83e), LL(0x28110a2d05051405), LL(0x1fe6ce7867678167),
    LL(0x7353d597e4e4b7e4), LL(0x25bb4e0227279c27), LL(0x3258827341411941), LL(0x2c9d0ba78b8b168b),
    LL(0x510153f6a7a7a6a7), LL(0xcf94fab27d7de97d), LL(0xdcfb374995956e95), LL(0x8e9fad56d8d847d8),
    LL(0x8b30eb70fbfbcbfb), LL(0x2371c1cdeeee9fee), LL(0xc791f8bb7c7ced7c), LL(0x17e3cc7166668566),
    LL(0xa68ea77bdddd53dd), LL(0xb84b2eaf17175c17), LL(0x02468e4547470147), LL(0x84dc211a9e9e429e),
    LL(0x1ec589d4caca0fca), LL(0x75995a582d2db42d), LL(0x9179632ebfbfc6bf), LL(0x381b0e3f07071c07),
    LL(0x012347acadad8ead), LL(0xea2fb4b05a5a755a), LL(0x6cb51bef83833683), LL(0x85ff66b63333cc33),
    LL(0x3ff2c65c63639163), LL(0x100a041202020802), LL(0x39384993aaaa92aa), LL(0xafa8e2de7171d971),
    LL(0x0ecf8dc6c8c807c8), LL(0xc87d32d119196419), LL(0x7270923b49493949), LL(0x869aaf5fd9d943d9),
    LL(0xc31df931f2f2eff2), LL(0x4b48dba8e3e3abe3), LL(0xe22ab6b95b5b715b), LL(0x34920dbc88881a88),
    LL(0xa4c8293e9a9a529a), LL(0x2dbe4c0b26269826), LL(0x8dfa64bf3232c832), LL(0xe94a7d59b0b0fab0),
    LL(0x1b6acff2e9e983e9), LL(0x78331e770f0f3c0f), LL(0xe6a6b733d5d573d5), LL(0x74ba1df480803a80),
    LL(0x997c6127bebec2be), LL(0x26de87ebcdcd13cd), LL(0xbde468893434d034), LL(0x7a75903248483d48),
    LL(0xab24e354ffffdbff), LL(0xf78ff48d7a7af57a), LL(0xf4ea3d6490907a90), LL(0xc23ebe9d5f5f615f),
    LL(0x1da0403d20208020), LL(0x67d5d00f6868bd68), LL(0xd07234ca1a1a681a), LL(0x192c41b7aeae82ae),
    LL(0xc95e757db4b4eab4), LL(0x9a19a8ce54544d54), LL(0xece53b7f93937693), LL(0x0daa442f22228822),
    LL(0x07e9c86364648d64), LL(0xdb12ff2af1f1e3f1), LL(0xbfa2e6cc7373d173), LL(0x905a248212124812),
    LL(0x3a5d807a40401d40), LL(0x4028104808082008), LL(0x56e89b95c3c32bc3), LL(0x337bc5dfecec97ec),
    LL(0x9690ab4ddbdb4bdb), LL(0x611f5fc0a1a1bea1), LL(0x1c8307918d8d0e8d), LL(0xf5c97ac83d3df43d),
    LL(0xccf1335b97976697), LL(0x0000000000000000), LL(0x36d483f9cfcf1bcf), LL(0x4587566e2b2bac2b),
    LL(0x97b3ece17676c576), LL(0x64b019e682823282), LL(0xfea9b128d6d67fd6), LL(0xd87736c31b1b6c1b),
    LL(0xc15b7774b5b5eeb5), LL(0x112943beafaf86af), LL(0x77dfd41d6a6ab56a), LL(0xba0da0ea50505d50),
    LL(0x124c8a5745450945), LL(0xcb18fb38f3f3ebf3), LL(0x9df060ad3030c030), LL(0x2b74c3c4efef9bef),
    LL(0xe5c37eda3f3ffc3f), LL(0x921caac755554955), LL(0x791059dba2a2b2a2), LL(0x0365c9e9eaea8fea),
    LL(0x0fecca6a65658965), LL(0xb9686903babad2ba), LL(0x65935e4a2f2fbc2f), LL(0x4ee79d8ec0c027c0),
    LL(0xbe81a160dede5fde), LL(0xe06c38fc1c1c701c), LL(0xbb2ee746fdfdd3fd), LL(0x52649a1f4d4d294d),
    LL(0xe4e0397692927292), LL(0x8fbceafa7575c975), LL(0x301e0c3606061806), LL(0x249809ae8a8a128a),
    LL(0xf940794bb2b2f2b2), LL(0x6359d185e6e6bfe6), LL(0x70361c7e0e0e380e), LL(0xf8633ee71f1f7c1f),
    LL(0x37f7c45562629562), LL(0xeea3b53ad4d477d4), LL(0x29324d81a8a89aa8), LL(0xc4f4315296966296),
    LL(0x9b3aef62f9f9c3f9), LL(0x66f697a3c5c533c5), LL(0x35b14a1025259425), LL(0xf220b2ab59597959),
    LL(0x54ae15d084842a84), LL(0xb7a7e4c57272d572), LL(0xd5dd72ec3939e439), LL(0x5a6198164c4c2d4c),
    LL(0xca3bbc945e5e655e), LL(0xe785f09f7878fd78), LL(0xddd870e53838e038), LL(0x148605988c8c0a8c),
    LL(0xc6b2bf17d1d163d1), LL(0x410b57e4a5a5aea5), LL(0x434dd9a1e2e2afe2), LL(0x2ff8c24e61619961),
    LL(0xf1457b42b3b3f6b3), LL(0x15a5423421218421), LL(0x94d625089c9c4a9c), LL(0xf0663cee1e1e781e),
    LL(0x2252866143431143), LL(0x76fc93b1c7c73bc7), LL(0xb32be54ffcfcd7fc), LL(0x2014082404041004),
    LL(0xb208a2e351515951), LL(0xbcc72f2599995e99), LL(0x4fc4da226d6da96d), LL(0x68391a650d0d340d),
    LL(0x8335e979fafacffa), LL(0xb684a369dfdf5bdf), LL(0xd79bfca97e7ee57e), LL(0x3db4481924249024),
    LL(0xc5d776fe3b3bec3b), LL(0x313d4b9aabab96ab), LL(0x3ed181f0cece1fce), LL(0x8855229911114411),
    LL(0x0c8903838f8f068f), LL(0x4a6b9c044e4e254e), LL(0xd1517366b7b7e6b7), LL(0x0b60cbe0ebeb8beb),
    LL(0xfdcc78c13c3cf03c), LL(0x7cbf1ffd81813e81), LL(0xd4fe354094946a94), LL(0xeb0cf31cf7f7fbf7),
    LL(0xa1676f18b9b9deb9), LL(0x985f268b13134c13), LL(0x7d9c58512c2cb02c), LL(0xd6b8bb05d3d36bd3),
    LL(0x6b5cd38ce7e7bbe7), LL(0x57cbdc396e6ea56e), LL(0x6ef395aac4c437c4), LL(0x180f061b03030c03),
    LL(0x8a13acdc56564556), LL(0x1a49885e44440d44), LL(0xdf9efea07f7fe17f), LL(0x21374f88a9a99ea9),
    LL(0x4d8254672a2aa82a), LL(0xb16d6b0abbbbd6bb), LL(0x46e29f87c1c123c1), LL(0xa202a6f153535153),
    LL(0xae8ba572dcdc57dc), LL(0x582716530b0b2c0b), LL(0x9cd327019d9d4e9d), LL(0x47c1d82b6c6cad6c),
    LL(0x95f562a43131c431), LL(0x87b9e8f37474cd74), LL(0xe309f115f6f6fff6), LL(0x0a438c4c46460546),
    LL(0x092645a5acac8aac), LL(0x3c970fb589891e89), LL(0xa04428b414145014), LL(0x5b42dfbae1e1a3e1),
    LL(0xb04e2ca616165816), LL(0xcdd274f73a3ae83a), LL(0x6fd0d2066969b969), LL(0x482d124109092409),
    LL(0xa7ade0d77070dd70), LL(0xd954716fb6b6e2b6), LL(0xceb7bd1ed0d067d0), LL(0x3b7ec7d6eded93ed),
    LL(0x2edb85e2cccc17cc), LL(0x2a57846842421542), LL(0xb4c22d2c98985a98), LL(0x490e55eda4a4aaa4),
    LL(0x5d8850752828a028), LL(0xda31b8865c5c6d5c), LL(0x933fed6bf8f8c7f8), LL(0x44a411c286862286),
};

static const u64 C5[256] = {
    LL(0x18c07830d8181860), LL(0x2305af462623238c), LL(0xc67ef991b8c6c63f), LL(0xe8136fcdfbe8e887),
    LL(0x874ca113cb878726), LL(0xb8a9626d11b8b8da), LL(0x0108050209010104), LL(0x4f426e9e0d4f4f21),
    LL(0x36adee6c9b3636d8), LL(0xa6590451ffa6a6a2), LL(0xd2debdb90cd2d26f), LL(0xf5fb06f70ef5f5f3),
    LL(0x79ef80f2967979f9), LL(0x6f5fcede306f6fa1), LL(0x91fcef3f6d91917e), LL(0x52aa07a4f8525255),
    LL(0x6027fdc04760609d), LL(0xbc89766535bcbcca), LL(0x9baccd2b379b9b56), LL(0x8e048c018a8e8e02),
    LL(0xa371155bd2a3a3b6), LL(0x0c603c186c0c0c30), LL(0x7bff8af6847b7bf1), LL(0x35b5e16a803535d4),
    LL(0x1de8693af51d1d74), LL(0xe05347ddb3e0e0a7), LL(0xd7f6acb321d7d77b), LL(0xc25eed999cc2c22f),
    LL(0x2e6d965c432e2eb8), LL(0x4b627a96294b4b31), LL(0xfea321e15dfefedf), LL(0x578216aed5575741),
    LL(0x15a8412abd151554), LL(0x779fb6eee87777c1), LL(0x37a5eb6e923737dc), LL(0xe57b56d79ee5e5b3),
    LL(0x9f8cd923139f9f46), LL(0xf0d317fd23f0f0e7), LL(0x4a6a7f94204a4a35), LL(0xda9e95a944dada4f),
    LL(0x58fa25b0a258587d), LL(0xc906ca8fcfc9c903), LL(0x29558d527c2929a4), LL(0x0a5022145a0a0a28),
    LL(0xb1e14f7f50b1b1fe), LL(0xa0691a5dc9a0a0ba), LL(0x6b7fdad6146b6bb1), LL(0x855cab17d985852e),
    LL(0xbd8173673cbdbdce), LL(0x5dd234ba8f5d5d69), LL(0x1080502090101040), LL(0xf4f303f507f4f4f7),
    LL(0xcb16c08bddcbcb0b), LL(0x3eedc67cd33e3ef8), LL(0x0528110a2d050514), LL(0x671fe6ce78676781),
    LL(0xe47353d597e4e4b7), LL(0x2725bb4e0227279c), LL(0x4132588273414119), LL(0x8b2c9d0ba78b8b16),
    LL(0xa7510153f6a7a7a6), LL(0x7dcf94fab27d7de9), LL(0x95dcfb374995956e), LL(0xd88e9fad56d8d847),
    LL(0xfb8b30eb70fbfbcb), LL(0xee2371c1cdeeee9f), LL(0x7cc791f8bb7c7ced), LL(0x6617e3cc71666685),
    LL(0xdda68ea77bdddd53), LL(0x17b84b2eaf17175c), LL(0x4702468e45474701), LL(0x9e84dc211a9e9e42),
    LL(0xca1ec589d4caca0f), LL(0x2d75995a582d2db4), LL(0xbf9179632ebfbfc6), LL(0x07381b0e3f07071c),
    LL(0xad012347acadad8e), LL(0x5aea2fb4b05a5a75), LL(0x836cb51bef838336), LL(0x3385ff66b63333cc),
    LL(0x633ff2c65c636391), LL(0x02100a0412020208), LL(0xaa39384993aaaa92), LL(0x71afa8e2de7171d9),
    LL(0xc80ecf8dc6c8c807), LL(0x19c87d32d1191964), LL(0x497270923b494939), LL(0xd9869aaf5fd9d943),
    LL(0xf2c31df931f2f2ef), LL(0xe34b48dba8e3e3ab), LL(0x5be22ab6b95b5b71), LL(0x8834920dbc88881a),
    LL(0x9aa4c8293e9a9a52), LL(0x262dbe4c0b262698), LL(0x328dfa64bf3232c8), LL(0xb0e94a7d59b0b0fa),
    LL(0xe91b6acff2e9e983), LL(0x0f78331e770f0f3c), LL(0xd5e6a6b733d5d573), LL(0x8074ba1df480803a),
    LL(0xbe997c6127bebec2), LL(0xcd26de87ebcdcd13), LL(0x34bde468893434d0), LL(0x487a75903248483d),
    LL(0xffab24e354ffffdb), LL(0x7af78ff48d7a7af5), LL(0x90f4ea3d6490907a), LL(0x5fc23ebe9d5f5f61),
    LL(0x201da0403d202080), LL(0x6867d5d00f6868bd), LL(0x1ad07234ca1a1a68), LL(0xae192c41b7aeae82),
    LL(0xb4c95e757db4b4ea), LL(0x549a19a8ce54544d), LL(0x93ece53b7f939376), LL(0x220daa442f222288),
    LL(0x6407e9c86364648d), LL(0xf1db12ff2af1f1e3), LL(0x73bfa2e6cc7373d1), LL(0x12905a2482121248),
    LL(0x403a5d807a40401d), LL(0x0840281048080820), LL(0xc356e89b95c3c32b), LL(0xec337bc5dfecec97),
    LL(0xdb9690ab4ddbdb4b), LL(0xa1611f5fc0a1a1be), LL(0x8d1c8307918d8d0e), LL(0x3df5c97ac83d3df4),
    LL(0x97ccf1335b979766), LL(0x0000000000000000), LL(0xcf36d483f9cfcf1b), LL(0x2b4587566e2b2bac),
    LL(0x7697b3ece17676c5), LL(0x8264b019e6828232), LL(0xd6fea9b128d6d67f), LL(0x1bd87736c31b1b6c),
    LL(0xb5c15b7774b5b5ee), LL(0xaf112943beafaf86), LL(0x6a77dfd41d6a6ab5), LL(0x50ba0da0ea50505d),
    LL(0x45124c8a57454509), LL(0xf3cb18fb38f3f3eb), LL(0x309df060ad3030c0), LL(0xef2b74c3c4efef9b),
    LL(0x3fe5c37eda3f3ffc), LL(0x55921caac7555549), LL(0xa2791059dba2a2b2), LL(0xea0365c9e9eaea8f),
    LL(0x650fecca6a656589), LL(0xbab9686903babad2), LL(0x2f65935e4a2f2fbc), LL(0xc04ee79d8ec0c027),
    LL(0xdebe81a160dede5f), LL(0x1ce06c38fc1c1c70), LL(0xfdbb2ee746fdfdd3), LL(0x4d52649a1f4d4d29),
    LL(0x92e4e03976929272), LL(0x758fbceafa7575c9), LL(0x06301e0c36060618), LL(0x8a249809ae8a8a12),
    LL(0xb2f940794bb2b2f2), LL(0xe66359d185e6e6bf), LL(0x0e70361c7e0e0e38), LL(0x1ff8633ee71f1f7c),
    LL(0x6237f7c455626295), LL(0xd4eea3b53ad4d477), LL(0xa829324d81a8a89a), LL(0x96c4f43152969662),
    LL(0xf99b3aef62f9f9c3), LL(0xc566f697a3c5c533), LL(0x2535b14a10252594), LL(0x59f220b2ab595979),
    LL(0x8454ae15d084842a), LL(0x72b7a7e4c57272d5), LL(0x39d5dd72ec3939e4), LL(0x4c5a6198164c4c2d),
    LL(0x5eca3bbc945e5e65), LL(0x78e785f09f7878fd), LL(0x38ddd870e53838e0), LL(0x8c148605988c8c0a),
    LL(0xd1c6b2bf17d1d163), LL(0xa5410b57e4a5a5ae), LL(0xe2434dd9a1e2e2af), LL(0x612ff8c24e616199),
    LL(0xb3f1457b42b3b3f6), LL(0x2115a54234212184), LL(0x9c94d625089c9c4a), LL(0x1ef0663cee1e1e78),
    LL(0x4322528661434311), LL(0xc776fc93b1c7c73b), LL(0xfcb32be54ffcfcd7), LL(0x0420140824040410),
    LL(0x51b208a2e3515159), LL(0x99bcc72f2599995e), LL(0x6d4fc4da226d6da9), LL(0x0d68391a650d0d34),
    LL(0xfa8335e979fafacf), LL(0xdfb684a369dfdf5b), LL(0x7ed79bfca97e7ee5), LL(0x243db44819242490),
    LL(0x3bc5d776fe3b3bec), LL(0xab313d4b9aabab96), LL(0xce3ed181f0cece1f), LL(0x1188552299111144),
    LL(0x8f0c8903838f8f06), LL(0x4e4a6b9c044e4e25), LL(0xb7d1517366b7b7e6), LL(0xeb0b60cbe0ebeb8b),
    LL(0x3cfdcc78c13c3cf0), LL(0x817cbf1ffd81813e), LL(0x94d4fe354094946a), LL(0xf7eb0cf31cf7f7fb),
    LL(0xb9a1676f18b9b9de), LL(0x13985f268b13134c), LL(0x2c7d9c58512c2cb0), LL(0xd3d6b8bb05d3d36b),
    LL(0xe76b5cd38ce7e7bb), LL(0x6e57cbdc396e6ea5), LL(0xc46ef395aac4c437), LL(0x03180f061b03030c),
    LL(0x568a13acdc565645), LL(0x441a49885e44440d), LL(0x7fdf9efea07f7fe1), LL(0xa921374f88a9a99e),
    LL(0x2a4d8254672a2aa8), LL(0xbbb16d6b0abbbbd6), LL(0xc146e29f87c1c123), LL(0x53a202a6f1535351),
    LL(0xdcae8ba572dcdc57), LL(0x0b582716530b0b2c), LL(0x9d9cd327019d9d4e), LL(0x6c47c1d82b6c6cad),
    LL(0x3195f562a43131c4), LL(0x7487b9e8f37474cd), LL(0xf6e309f115f6f6ff), LL(0x460a438c4c464605),
    LL(0xac092645a5acac8a), LL(0x893c970fb589891e), LL(0x14a04428b4141450), LL(0xe15b42dfbae1e1a3),
    LL(0x16b04e2ca6161658), LL(0x3acdd274f73a3ae8), LL(0x696fd0d2066969b9), LL(0x09482d1241090924),
    LL(0x70a7ade0d77070dd), LL(0xb6d954716fb6b6e2), LL(0xd0ceb7bd1ed0d067), LL(0xed3b7ec7d6eded93),
    LL(0xcc2edb85e2cccc17), LL(0x422a578468424215), LL(0x98b4c22d2c98985a), LL(0xa4490e55eda4a4aa),
    LL(0x285d8850752828a0), LL(0x5cda31b8865c5c6d), LL(0xf8933fed6bf8f8c7), LL(0x8644a411c2868622),
};

static const u64 C6[256] = {
    LL(0x6018c07830d81818), LL(0x8c2305af46262323), LL(0x3fc67ef991b8c6c6), LL(0x87e8136fcdfbe8e8),
    LL(0x26874ca113cb8787), LL(0xdab8a9626d11b8b8), LL(0x0401080502090101), LL(0x214f426e9e0d4f4f),
    LL(0xd836adee6c9b3636), LL(0xa2a6590451ffa6a6), LL(0x6fd2debdb90cd2d2), LL(0xf3f5fb06f70ef5f5),
    LL(0xf979ef80f2967979), LL(0xa16f5fcede306f6f), LL(0x7e91fcef3f6d9191), LL(0x5552aa07a4f85252),
    LL(0x9d6027fdc0476060), LL(0xcabc89766535bcbc), LL(0x569baccd2b379b9b), LL(0x028e048c018a8e8e),
    LL(0xb6a371155bd2a3a3), LL(0x300c603c186c0c0c), LL(0xf17bff8af6847b7b), LL(0xd435b5e16a803535),
    LL(0x741de8693af51d1d), LL(0xa7e05347ddb3e0e0), LL(0x7bd7f6acb321d7d7), LL(0x2fc25eed999cc2c2),
    LL(0xb82e6d965c432e2e), LL(0x314b627a96294b4b), LL(0xdffea321e15dfefe), LL(0x41578216aed55757),
    LL(0x5415a8412abd1515), LL(0xc1779fb6eee87777), LL(0xdc37a5eb6e923737), LL(0xb3e57b56d79ee5e5),
    LL(0x469f8cd923139f9f), LL(0xe7f0d317fd23f0f0), LL(0x354a6a7f94204a4a), LL(0x4fda9e95a944dada),
    LL(0x7d58fa25b0a25858), LL(0x03c906ca8fcfc9c9), LL(0xa429558d527c2929), LL(0x280a5022145a0a0a),
    LL(0xfeb1e14f7f50b1b1), LL(0xbaa0691a5dc9a0a0), LL(0xb16b7fdad6146b6b), LL(0x2e855cab17d98585),
    LL(0xcebd8173673cbdbd), LL(0x695dd234ba8f5d5d), LL(0x4010805020901010), LL(0xf7f4f303f507f4f4),
    LL(0x0bcb16c08bddcbcb), LL(0xf83eedc67cd33e3e), LL(0x140528110a2d0505), LL(0x81671fe6ce786767),
    LL(0xb7e47353d597e4e4), LL(0x9c2725bb4e022727), LL(0x1941325882734141), LL(0x168b2c9d0ba78b8b),
    LL(0xa6a7510153f6a7a7), LL(0xe97dcf94fab27d7d), LL(0x6e95dcfb37499595), LL(0x47d88e9fad56d8d8),
    LL(0xcbfb8b30eb70fbfb), LL(0x9fee2371c1cdeeee), LL(0xed7cc791f8bb7c7c), LL(0x856617e3cc716666),
    LL(0x53dda68ea77bdddd), LL(0x5c17b84b2eaf1717), LL(0x014702468e454747), LL(0x429e84dc211a9e9e),
    LL(0x0fca1ec589d4caca), LL(0xb42d75995a582d2d), LL(0xc6bf9179632ebfbf), LL(0x1c07381b0e3f0707),
    LL(0x8ead012347acadad), LL(0x755aea2fb4b05a5a), LL(0x36836cb51bef8383), LL(0xcc3385ff66b63333),
    LL(0x91633ff2c65c6363), LL(0x0802100a04120202), LL(0x92aa39384993aaaa), LL(0xd971afa8e2de7171),
    LL(0x07c80ecf8dc6c8c8), LL(0x6419c87d32d11919), LL(0x39497270923b4949), LL(0x43d9869aaf5fd9d9),
    LL(0xeff2c31df931f2f2), LL(0xabe34b48dba8e3e3), LL(0x715be22ab6b95b5b), LL(0x1a8834920dbc8888),
    LL(0x529aa4c8293e9a9a), LL(0x98262dbe4c0b2626), LL(0xc8328dfa64bf3232), LL(0xfab0e94a7d59b0b0),
    LL(0x83e91b6acff2e9e9), LL(0x3c0f78331e770f0f), LL(0x73d5e6a6b733d5d5), LL(0x3a8074ba1df48080),
    LL(0xc2be997c6127bebe), LL(0x13cd26de87ebcdcd), LL(0xd034bde468893434), LL(0x3d487a7590324848),
    LL(0xdbffab24e354ffff), LL(0xf57af78ff48d7a7a), LL(0x7a90f4ea3d649090), LL(0x615fc23ebe9d5f5f),
    LL(0x80201da0403d2020), LL(0xbd6867d5d00f6868), LL(0x681ad07234ca1a1a), LL(0x82ae192c41b7aeae),
    LL(0xeab4c95e757db4b4), LL(0x4d549a19a8ce5454), LL(0x7693ece53b7f9393), LL(0x88220daa442f2222),
    LL(0x8d6407e9c8636464), LL(0xe3f1db12ff2af1f1), LL(0xd173bfa2e6cc7373), LL(0x4812905a24821212),
    LL(0x1d403a5d807a4040), LL(0x2008402810480808), LL(0x2bc356e89b95c3c3), LL(0x97ec337bc5dfecec),
    LL(0x4bdb9690ab4ddbdb), LL(0xbea1611f5fc0a1a1), LL(0x0e8d1c8307918d8d), LL(0xf43df5c97ac83d3d),
    LL(0x6697ccf1335b9797), LL(0x0000000000000000), LL(0x1bcf36d483f9cfcf), LL(0xac2b4587566e2b2b),
    LL(0xc57697b3ece17676), LL(0x328264b019e68282), LL(0x7fd6fea9b128d6d6), LL(0x6c1bd87736c31b1b),
    LL(0xeeb5c15b7774b5b5), LL(0x86af112943beafaf), LL(0xb56a77dfd41d6a6a), LL(0x5d50ba0da0ea5050),
    LL(0x0945124c8a574545), LL(0xebf3cb18fb38f3f3), LL(0xc0309df060ad3030), LL(0x9bef2b74c3c4efef),
    LL(0xfc3fe5c37eda3f3f), LL(0x4955921caac75555), LL(0xb2a2791059dba2a2), LL(0x8fea0365c9e9eaea),
    LL(0x89650fecca6a6565), LL(0xd2bab9686903baba), LL(0xbc2f65935e4a2f2f), LL(0x27c04ee79d8ec0c0),
    LL(0x5fdebe81a160dede), LL(0x701ce06c38fc1c1c), LL(0xd3fdbb2ee746fdfd), LL(0x294d52649a1f4d4d),
    LL(0x7292e4e039769292), LL(0xc9758fbceafa7575), LL(0x1806301e0c360606), LL(0x128a249809ae8a8a),
    LL(0xf2b2f940794bb2b2), LL(0xbfe66359d185e6e6), LL(0x380e70361c7e0e0e), LL(0x7c1ff8633ee71f1f),
    LL(0x956237f7c4556262), LL(0x77d4eea3b53ad4d4), LL(0x9aa829324d81a8a8), LL(0x6296c4f431529696),
    LL(0xc3f99b3aef62f9f9), LL(0x33c566f697a3c5c5), LL(0x942535b14a102525), LL(0x7959f220b2ab5959),
    LL(0x2a8454ae15d08484), LL(0xd572b7a7e4c57272), LL(0xe439d5dd72ec3939), LL(0x2d4c5a6198164c4c),
    LL(0x655eca3bbc945e5e), LL(0xfd78e785f09f7878), LL(0xe038ddd870e53838), LL(0x0a8c148605988c8c),
    LL(0x63d1c6b2bf17d1d1), LL(0xaea5410b57e4a5a5), LL(0xafe2434dd9a1e2e2), LL(0x99612ff8c24e6161),
    LL(0xf6b3f1457b42b3b3), LL(0x842115a542342121), LL(0x4a9c94d625089c9c), LL(0x781ef0663cee1e1e),
    LL(0x1143225286614343), LL(0x3bc776fc93b1c7c7), LL(0xd7fcb32be54ffcfc), LL(0x1004201408240404),
    LL(0x5951b208a2e35151), LL(0x5e99bcc72f259999), LL(0xa96d4fc4da226d6d), LL(0x340d68391a650d0d),
    LL(0xcffa8335e979fafa), LL(0x5bdfb684a369dfdf), LL(0xe57ed79bfca97e7e), LL(0x90243db448192424),
    LL(0xec3bc5d776fe3b3b), LL(0x96ab313d4b9aabab), LL(0x1fce3ed181f0cece), LL(0x4411885522991111),
    LL(0x068f0c8903838f8f), LL(0x254e4a6b9c044e4e), LL(0xe6b7d1517366b7b7), LL(0x8beb0b60cbe0ebeb),
    LL(0xf03cfdcc78c13c3c), LL(0x3e817cbf1ffd8181), LL(0x6a94d4fe35409494), LL(0xfbf7eb0cf31cf7f7),
    LL(0xdeb9a1676f18b9b9), LL(0x4c13985f268b1313), LL(0xb02c7d9c58512c2c), LL(0x6bd3d6b8bb05d3d3),
    LL(0xbbe76b5cd38ce7e7), LL(0xa56e57cbdc396e6e), LL(0x37c46ef395aac4c4), LL(0x0c03180f061b0303),
    LL(0x45568a13acdc5656), LL(0x0d441a49885e4444), LL(0xe17fdf9efea07f7f), LL(0x9ea921374f88a9a9),
    LL(0xa82a4d8254672a2a), LL(0xd6bbb16d6b0abbbb), LL(0x23c146e29f87c1c1), LL(0x5153a202a6f15353),
    LL(0x57dcae8ba572dcdc), LL(0x2c0b582716530b0b), LL(0x4e9d9cd327019d9d), LL(0xad6c47c1d82b6c6c),
    LL(0xc43195f562a43131), LL(0xcd7487b9e8f37474), LL(0xfff6e309f115f6f6), LL(0x05460a438c4c4646),
    LL(0x8aac092645a5acac), LL(0x1e893c970fb58989), LL(0x5014a04428b41414), LL(0xa3e15b42dfbae1e1),
    LL(0x5816b04e2ca61616), LL(0xe83acdd274f73a3a), LL(0xb9696fd0d2066969), LL(0x2409482d12410909),
    LL(0xdd70a7ade0d77070), LL(0xe2b6d954716fb6b6), LL(0x67d0ceb7bd1ed0d0), LL(0x93ed3b7ec7d6eded),
    LL(0x17cc2edb85e2cccc), LL(0x15422a5784684242), LL(0x5a98b4c22d2c9898), LL(0xaaa4490e55eda4a4),
    LL(0xa0285d8850752828), LL(0x6d5cda31b8865c5c), LL(0xc7f8933fed6bf8f8), LL(0x228644a411c28686),
};

static const u64 C7[256] = {
    LL(0x186018c07830d818), LL(0x238c2305af462623), LL(0xc63fc67ef991b8c6), LL(0xe887e8136fcdfbe8),
    LL(0x8726874ca113cb87), LL(0xb8dab8a9626d11b8), LL(0x0104010805020901), LL(0x4f214f426e9e0d4f),
    LL(0x36d836adee6c9b36), LL(0xa6a2a6590451ffa6), LL(0xd26fd2debdb90cd2), LL(0xf5f3f5fb06f70ef5),
    LL(0x79f979ef80f29679), LL(0x6fa16f5fcede306f), LL(0x917e91fcef3f6d91), LL(0x525552aa07a4f852),
    LL(0x609d6027fdc04760), LL(0xbccabc89766535bc), LL(0x9b569baccd2b379b), LL(0x8e028e048c018a8e),
    LL(0xa3b6a371155bd2a3), LL(0x0c300c603c186c0c), LL(0x7bf17bff8af6847b), LL(0x35d435b5e16a8035),
    LL(0x1d741de8693af51d), LL(0xe0a7e05347ddb3e0), LL(0xd77bd7f6acb321d7), LL(0xc22fc25eed999cc2),
    LL(0x2eb82e6d965c432e), LL(0x4b314b627a96294b), LL(0xfedffea321e15dfe), LL(0x5741578216aed557),
    LL(0x155415a8412abd15), LL(0x77c1779fb6eee877), LL(0x37dc37a5eb6e9237), LL(0xe5b3e57b56d79ee5),
    LL(0x9f469f8cd923139f), LL(0xf0e7f0d317fd23f0), LL(0x4a354a6a7f94204a), LL(0xda4fda9e95a944da),
    LL(0x587d58fa25b0a258), LL(0xc903c906ca8fcfc9), LL(0x29a429558d527c29), LL(0x0a280a5022145a0a),
    LL(0xb1feb1e14f7f50b1), LL(0xa0baa0691a5dc9a0), LL(0x6bb16b7fdad6146b), LL(0x852e855cab17d985),
    LL(0xbdcebd8173673cbd), LL(0x5d695dd234ba8f5d), LL(0x1040108050209010), LL(0xf4f7f4f303f507f4),
    LL(0xcb0bcb16c08bddcb), LL(0x3ef83eedc67cd33e), LL(0x05140528110a2d05), LL(0x6781671fe6ce7867),
    LL(0xe4b7e47353d597e4), LL(0x279c2725bb4e0227), LL(0x4119413258827341), LL(0x8b168b2c9d0ba78b),
    LL(0xa7a6a7510153f6a7), LL(0x7de97dcf94fab27d), LL(0x956e95dcfb374995), LL(0xd847d88e9fad56d8),
    LL(0xfbcbfb8b30eb70fb), LL(0xee9fee2371c1cdee), LL(0x7ced7cc791f8bb7c), LL(0x66856617e3cc7166),
    LL(0xdd53dda68ea77bdd), LL(0x175c17b84b2eaf17), LL(0x47014702468e4547), LL(0x9e429e84dc211a9e),
    LL(0xca0fca1ec589d4ca), LL(0x2db42d75995a582d), LL(0xbfc6bf9179632ebf), LL(0x071c07381b0e3f07),
    LL(0xad8ead012347acad), LL(0x5a755aea2fb4b05a), LL(0x8336836cb51bef83), LL(0x33cc3385ff66b633),
    LL(0x6391633ff2c65c63), LL(0x020802100a041202), LL(0xaa92aa39384993aa), LL(0x71d971afa8e2de71),
    LL(0xc807c80ecf8dc6c8), LL(0x196419c87d32d119), LL(0x4939497270923b49), LL(0xd943d9869aaf5fd9),
    LL(0xf2eff2c31df931f2), LL(0xe3abe34b48dba8e3), LL(0x5b715be22ab6b95b), LL(0x881a8834920dbc88),
    LL(0x9a529aa4c8293e9a), LL(0x2698262dbe4c0b26), LL(0x32c8328dfa64bf32), LL(0xb0fab0e94a7d59b0),
    LL(0xe983e91b6acff2e9), LL(0x0f3c0f78331e770f), LL(0xd573d5e6a6b733d5), LL(0x803a8074ba1df480),
    LL(0xbec2be997c6127be), LL(0xcd13cd26de87ebcd), LL(0x34d034bde4688934), LL(0x483d487a75903248),
    LL(0xffdbffab24e354ff), LL(0x7af57af78ff48d7a), LL(0x907a90f4ea3d6490), LL(0x5f615fc23ebe9d5f),
    LL(0x2080201da0403d20), LL(0x68bd6867d5d00f68), LL(0x1a681ad07234ca1a), LL(0xae82ae192c41b7ae),
    LL(0xb4eab4c95e757db4), LL(0x544d549a19a8ce54), LL(0x937693ece53b7f93), LL(0x2288220daa442f22),
    LL(0x648d6407e9c86364), LL(0xf1e3f1db12ff2af1), LL(0x73d173bfa2e6cc73), LL(0x124812905a248212),
    LL(0x401d403a5d807a40), LL(0x0820084028104808), LL(0xc32bc356e89b95c3), LL(0xec97ec337bc5dfec),
    LL(0xdb4bdb9690ab4ddb), LL(0xa1bea1611f5fc0a1), LL(0x8d0e8d1c8307918d), LL(0x3df43df5c97ac83d),
    LL(0x976697ccf1335b97), LL(0x0000000000000000), LL(0xcf1bcf36d483f9cf), LL(0x2bac2b4587566e2b),
    LL(0x76c57697b3ece176), LL(0x82328264b019e682), LL(0xd67fd6fea9b128d6), LL(0x1b6c1bd87736c31b),
    LL(0xb5eeb5c15b7774b5), LL(0xaf86af112943beaf), LL(0x6ab56a77dfd41d6a), LL(0x505d50ba0da0ea50),
    LL(0x450945124c8a5745), LL(0xf3ebf3cb18fb38f3), LL(0x30c0309df060ad30), LL(0xef9bef2b74c3c4ef),
    LL(0x3ffc3fe5c37eda3f), LL(0x554955921caac755), LL(0xa2b2a2791059dba2), LL(0xea8fea0365c9e9ea),
    LL(0x6589650fecca6a65), LL(0xbad2bab9686903ba), LL(0x2fbc2f65935e4a2f), LL(0xc027c04ee79d8ec0),
    LL(0xde5fdebe81a160de), LL(0x1c701ce06c38fc1c), LL(0xfdd3fdbb2ee746fd), LL(0x4d294d52649a1f4d),
    LL(0x927292e4e0397692), LL(0x75c9758fbceafa75), LL(0x061806301e0c3606), LL(0x8a128a249809ae8a),
    LL(0xb2f2b2f940794bb2), LL(0xe6bfe66359d185e6), LL(0x0e380e70361c7e0e), LL(0x1f7c1ff8633ee71f),
    LL(0x62956237f7c45562), LL(0xd477d4eea3b53ad4), LL(0xa89aa829324d81a8), LL(0x966296c4f4315296),
    LL(0xf9c3f99b3aef62f9), LL(0xc533c566f697a3c5), LL(0x25942535b14a1025), LL(0x597959f220b2ab59),
    LL(0x842a8454ae15d084), LL(0x72d572b7a7e4c572), LL(0x39e439d5dd72ec39), LL(0x4c2d4c5a6198164c),
    LL(0x5e655eca3bbc945e), LL(0x78fd78e785f09f78), LL(0x38e038ddd870e538), LL(0x8c0a8c148605988c),
    LL(0xd163d1c6b2bf17d1), LL(0xa5aea5410b57e4a5), LL(0xe2afe2434dd9a1e2), LL(0x6199612ff8c24e61),
    LL(0xb3f6b3f1457b42b3), LL(0x21842115a5423421), LL(0x9c4a9c94d625089c), LL(0x1e781ef0663cee1e),
    LL(0x4311432252866143), LL(0xc73bc776fc93b1c7), LL(0xfcd7fcb32be54ffc), LL(0x0410042014082404),
    LL(0x515951b208a2e351), LL(0x995e99bcc72f2599), LL(0x6da96d4fc4da226d), LL(0x0d340d68391a650d),
    LL(0xfacffa8335e979fa), LL(0xdf5bdfb684a369df), LL(0x7ee57ed79bfca97e), LL(0x2490243db4481924),
    LL(0x3bec3bc5d776fe3b), LL(0xab96ab313d4b9aab), LL(0xce1fce3ed181f0ce), LL(0x1144118855229911),
    LL(0x8f068f0c8903838f), LL(0x4e254e4a6b9c044e), LL(0xb7e6b7d1517366b7), LL(0xeb8beb0b60cbe0eb),
    LL(0x3cf03cfdcc78c13c), LL(0x813e817cbf1ffd81), LL(0x946a94d4fe354094), LL(0xf7fbf7eb0cf31cf7),
    LL(0xb9deb9a1676f18b9), LL(0x134c13985f268b13), LL(0x2cb02c7d9c58512c), LL(0xd36bd3d6b8bb05d3),
    LL(0xe7bbe76b5cd38ce7), LL(0x6ea56e57cbdc396e), LL(0xc437c46ef395aac4), LL(0x030c03180f061b03),
    LL(0x5645568a13acdc56), LL(0x440d441a49885e44), LL(0x7fe17fdf9efea07f), LL(0xa99ea921374f88a9),
    LL(0x2aa82a4d8254672a), LL(0xbbd6bbb16d6b0abb), LL(0xc123c146e29f87c1), LL(0x535153a202a6f153),
    LL(0xdc57dcae8ba572dc), LL(0x0b2c0b582716530b), LL(0x9d4e9d9cd327019d), LL(0x6cad6c47c1d82b6c),
    LL(0x31c43195f562a431), LL(0x74cd7487b9e8f374), LL(0xf6fff6e309f115f6), LL(0x4605460a438c4c46),
    LL(0xac8aac092645a5ac), LL(0x891e893c970fb589), LL(0x145014a04428b414), LL(0xe1a3e15b42dfbae1),
    LL(0x165816b04e2ca616), LL(0x3ae83acdd274f73a), LL(0x69b9696fd0d20669), LL(0x092409482d124109),
    LL(0x70dd70a7ade0d770), LL(0xb6e2b6d954716fb6), LL(0xd067d0ceb7bd1ed0), LL(0xed93ed3b7ec7d6ed),
    LL(0xcc17cc2edb85e2cc), LL(0x4215422a57846842), LL(0x985a98b4c22d2c98), LL(0xa4aaa4490e55eda4),
    LL(0x28a0285d88507528), LL(0x5c6d5cda31b8865c), LL(0xf8c7f8933fed6bf8), LL(0x86228644a411c286),
};

#ifdef OBSOLETE
static const u64 C0[256] = {
    LL(0x1818281878c0d878), LL(0x23236523af0526af), LL(0xc6c657c6f97eb8f9), LL(0xe8e825e86f13fb6f),
    LL(0x87879487a14ccba1), LL(0xb8b8d5b862a91162), LL(0x0101030105080905), LL(0x4f4fd14f6e420d6e),
    LL(0x36365a36eead9bee), LL(0xa6a6f7a60459ff04), LL(0xd2d26bd2bdde0cbd), LL(0xf5f502f506fb0e06),
    LL(0x79798b7980ef9680), LL(0x6f6fb16fce5f30ce), LL(0x9191ae91effc6def), LL(0x5252f65207aaf807),
    LL(0x6060a060fd2747fd), LL(0xbcbcd9bc76893576), LL(0x9b9bb09bcdac37cd), LL(0x8e8e8f8e8c048a8c),
    LL(0xa3a3f8a31571d215), LL(0x0c0c140c3c606c3c), LL(0x7b7b8d7b8aff848a), LL(0x35355f35e1b580e1),
    LL(0x1d1d271d69e8f569), LL(0xe0e03de04753b347), LL(0xd7d764d7acf621ac), LL(0xc2c25bc2ed5e9ced),
    LL(0x2e2e722e966d4396), LL(0x4b4bdd4b7a62297a), LL(0xfefe1ffe21a35d21), LL(0x5757f9571682d516),
    LL(0x15153f1541a8bd41), LL(0x77779977b69fe8b6), LL(0x37375937eba592eb), LL(0xe5e532e5567b9e56),
    LL(0x9f9fbc9fd98c13d9), LL(0xf0f00df017d32317), LL(0x4a4ade4a7f6a207f), LL(0xdada73da959e4495),
    LL(0x5858e85825faa225), LL(0xc9c946c9ca06cfca), LL(0x29297b298d557c8d), LL(0x0a0a1e0a22505a22),
    LL(0xb1b1ceb14fe1504f), LL(0xa0a0fda01a69c91a), LL(0x6b6bbd6bda7f14da), LL(0x85859285ab5cd9ab),
    LL(0xbdbddabd73813c73), LL(0x5d5de75d34d28f34), LL(0x1010301050809050), LL(0xf4f401f403f30703),
    LL(0xcbcb40cbc016ddc0), LL(0x3e3e423ec6edd3c6), LL(0x05050f0511282d11), LL(0x6767a967e61f78e6),
    LL(0xe4e431e453739753), LL(0x27276927bb2502bb), LL(0x4141c34158327358), LL(0x8b8b808b9d2ca79d),
    LL(0xa7a7f4a70151f601), LL(0x7d7d877d94cfb294), LL(0x9595a295fbdc49fb), LL(0xd8d875d89f8e569f),
    LL(0xfbfb10fb308b7030), LL(0xeeee2fee7123cd71), LL(0x7c7c847c91c7bb91), LL(0x6666aa66e31771e3),
    LL(0xdddd7add8ea67b8e), LL(0x171739174bb8af4b), LL(0x4747c94746024546), LL(0x9e9ebf9edc841adc),
    LL(0xcaca43cac51ed4c5), LL(0x2d2d772d99755899), LL(0xbfbfdcbf79912e79), LL(0x070709071b383f1b),
    LL(0xadadeaad2301ac23), LL(0x5a5aee5a2feab02f), LL(0x83839883b56cefb5), LL(0x33335533ff85b6ff),
    LL(0x6363a563f23f5cf2), LL(0x020206020a10120a), LL(0xaaaae3aa38399338), LL(0x71719371a8afdea8),
    LL(0xc8c845c8cf0ec6cf), LL(0x19192b197dc8d17d), LL(0x4949db4970723b70), LL(0xd9d976d99a865f9a),
    LL(0xf2f20bf21dc3311d), LL(0xe3e338e3484ba848), LL(0x5b5bed5b2ae2b92a), LL(0x888885889234bc92),
    LL(0x9a9ab39ac8a43ec8), LL(0x26266a26be2d0bbe), LL(0x32325632fa8dbffa), LL(0xb0b0cdb04ae9594a),
    LL(0xe9e926e96a1bf26a), LL(0x0f0f110f33787733), LL(0xd5d562d5a6e633a6), LL(0x80809d80ba74f4ba),
    LL(0xbebedfbe7c99277c), LL(0xcdcd4acdde26ebde), LL(0x34345c34e4bd89e4), LL(0x4848d848757a3275),
    LL(0xffff1cff24ab5424), LL(0x7a7a8e7a8ff78d8f), LL(0x9090ad90eaf464ea), LL(0x5f5fe15f3ec29d3e),
    LL(0x20206020a01d3da0), LL(0x6868b868d5670fd5), LL(0x1a1a2e1a72d0ca72), LL(0xaeaeefae2c19b72c),
    LL(0xb4b4c1b45ec97d5e), LL(0x5454fc54199ace19), LL(0x9393a893e5ec7fe5), LL(0x22226622aa0d2faa),
    LL(0x6464ac64e90763e9), LL(0xf1f10ef112db2a12), LL(0x73739573a2bfcca2), LL(0x121236125a90825a),
    LL(0x4040c0405d3a7a5d), LL(0x0808180828404828), LL(0xc3c358c3e85695e8), LL(0xecec29ec7b33df7b),
    LL(0xdbdb70db90964d90), LL(0xa1a1fea11f61c01f), LL(0x8d8d8a8d831c9183), LL(0x3d3d473dc9f5c8c9),
    LL(0x9797a497f1cc5bf1), LL(0x0000000000000000), LL(0xcfcf4ccfd436f9d4), LL(0x2b2b7d2b87456e87),
    LL(0x76769a76b397e1b3), LL(0x82829b82b064e6b0), LL(0xd6d667d6a9fe28a9), LL(0x1b1b2d1b77d8c377),
    LL(0xb5b5c2b55bc1745b), LL(0xafafecaf2911be29), LL(0x6a6abe6adf771ddf), LL(0x5050f0500dbaea0d),
    LL(0x4545cf454c12574c), LL(0xf3f308f318cb3818), LL(0x30305030f09dadf0), LL(0xefef2cef742bc474),
    LL(0x3f3f413fc3e5dac3), LL(0x5555ff551c92c71c), LL(0xa2a2fba21079db10), LL(0xeaea23ea6503e965),
    LL(0x6565af65ec0f6aec), LL(0xbabad3ba68b90368), LL(0x2f2f712f93654a93), LL(0xc0c05dc0e74e8ee7),
    LL(0xdede7fde81be6081), LL(0x1c1c241c6ce0fc6c), LL(0xfdfd1afd2ebb462e), LL(0x4d4dd74d64521f64),
    LL(0x9292ab92e0e476e0), LL(0x75759f75bc8ffabc), LL(0x06060a061e30361e), LL(0x8a8a838a9824ae98),
    LL(0xb2b2cbb240f94b40), LL(0xe6e637e659638559), LL(0x0e0e120e36707e36), LL(0x1f1f211f63f8e763),
    LL(0x6262a662f73755f7), LL(0xd4d461d4a3ee3aa3), LL(0xa8a8e5a832298132), LL(0x9696a796f4c452f4),
    LL(0xf9f916f93a9b623a), LL(0xc5c552c5f666a3f6), LL(0x25256f25b13510b1), LL(0x5959eb5920f2ab20),
    LL(0x84849184ae54d0ae), LL(0x72729672a7b7c5a7), LL(0x39394b39ddd5ecdd), LL(0x4c4cd44c615a1661),
    LL(0x5e5ee25e3bca943b), LL(0x7878887885e79f85), LL(0x38384838d8dde5d8), LL(0x8c8c898c86149886),
    LL(0xd1d16ed1b2c617b2), LL(0xa5a5f2a50b41e40b), LL(0xe2e23be24d43a14d), LL(0x6161a361f82f4ef8),
    LL(0xb3b3c8b345f14245), LL(0x21216321a51534a5), LL(0x9c9cb99cd69408d6), LL(0x1e1e221e66f0ee66),
    LL(0x4343c54352226152), LL(0xc7c754c7fc76b1fc), LL(0xfcfc19fc2bb34f2b), LL(0x04040c0414202414),
    LL(0x5151f35108b2e308), LL(0x9999b699c7bc25c7), LL(0x6d6db76dc44f22c4), LL(0x0d0d170d39686539),
    LL(0xfafa13fa35837935), LL(0xdfdf7cdf84b66984), LL(0x7e7e827e9bd7a99b), LL(0x24246c24b43d19b4),
    LL(0x3b3b4d3bd7c5fed7), LL(0xababe0ab3d319a3d), LL(0xcece4fced13ef0d1), LL(0x1111331155889955),
    LL(0x8f8f8c8f890c8389), LL(0x4e4ed24e6b4a046b), LL(0xb7b7c4b751d16651), LL(0xebeb20eb600be060),
    LL(0x3c3c443cccfdc1cc), LL(0x81819e81bf7cfdbf), LL(0x9494a194fed440fe), LL(0xf7f704f70ceb1c0c),
    LL(0xb9b9d6b967a11867), LL(0x131335135f988b5f), LL(0x2c2c742c9c7d519c), LL(0xd3d368d3b8d605b8),
    LL(0xe7e734e75c6b8c5c), LL(0x6e6eb26ecb5739cb), LL(0xc4c451c4f36eaaf3), LL(0x030305030f181b0f),
    LL(0x5656fa56138adc13), LL(0x4444cc44491a5e49), LL(0x7f7f817f9edfa09e), LL(0xa9a9e6a937218837),
    LL(0x2a2a7e2a824d6782), LL(0xbbbbd0bb6db10a6d), LL(0xc1c15ec1e24687e2), LL(0x5353f55302a2f102),
    LL(0xdcdc79dc8bae728b), LL(0x0b0b1d0b27585327), LL(0x9d9dba9dd39c01d3), LL(0x6c6cb46cc1472bc1),
    LL(0x31315331f595a4f5), LL(0x74749c74b987f3b9), LL(0xf6f607f609e31509), LL(0x4646ca46430a4c43),
    LL(0xacace9ac2609a526), LL(0x89898689973cb597), LL(0x14143c1444a0b444), LL(0xe1e13ee1425bba42),
    LL(0x16163a164eb0a64e), LL(0x3a3a4e3ad2cdf7d2), LL(0x6969bb69d06f06d0), LL(0x09091b092d48412d),
    LL(0x70709070ada7d7ad), LL(0xb6b6c7b654d96f54), LL(0xd0d06dd0b7ce1eb7), LL(0xeded2aed7e3bd67e),
    LL(0xcccc49ccdb2ee2db), LL(0x4242c642572a6857), LL(0x9898b598c2b42cc2), LL(0xa4a4f1a40e49ed0e),
    LL(0x28287828885d7588), LL(0x5c5ce45c31da8631), LL(0xf8f815f83f936b3f), LL(0x86869786a444c2a4),
};

static const u64 C1[256] = {
    LL(0x781818281878c0d8), LL(0xaf23236523af0526), LL(0xf9c6c657c6f97eb8), LL(0x6fe8e825e86f13fb),
    LL(0xa187879487a14ccb), LL(0x62b8b8d5b862a911), LL(0x0501010301050809), LL(0x6e4f4fd14f6e420d),
    LL(0xee36365a36eead9b), LL(0x04a6a6f7a60459ff), LL(0xbdd2d26bd2bdde0c), LL(0x06f5f502f506fb0e),
    LL(0x8079798b7980ef96), LL(0xce6f6fb16fce5f30), LL(0xef9191ae91effc6d), LL(0x075252f65207aaf8),
    LL(0xfd6060a060fd2747), LL(0x76bcbcd9bc768935), LL(0xcd9b9bb09bcdac37), LL(0x8c8e8e8f8e8c048a),
    LL(0x15a3a3f8a31571d2), LL(0x3c0c0c140c3c606c), LL(0x8a7b7b8d7b8aff84), LL(0xe135355f35e1b580),
    LL(0x691d1d271d69e8f5), LL(0x47e0e03de04753b3), LL(0xacd7d764d7acf621), LL(0xedc2c25bc2ed5e9c),
    LL(0x962e2e722e966d43), LL(0x7a4b4bdd4b7a6229), LL(0x21fefe1ffe21a35d), LL(0x165757f9571682d5),
    LL(0x4115153f1541a8bd), LL(0xb677779977b69fe8), LL(0xeb37375937eba592), LL(0x56e5e532e5567b9e),
    LL(0xd99f9fbc9fd98c13), LL(0x17f0f00df017d323), LL(0x7f4a4ade4a7f6a20), LL(0x95dada73da959e44),
    LL(0x255858e85825faa2), LL(0xcac9c946c9ca06cf), LL(0x8d29297b298d557c), LL(0x220a0a1e0a22505a),
    LL(0x4fb1b1ceb14fe150), LL(0x1aa0a0fda01a69c9), LL(0xda6b6bbd6bda7f14), LL(0xab85859285ab5cd9),
    LL(0x73bdbddabd73813c), LL(0x345d5de75d34d28f), LL(0x5010103010508090), LL(0x03f4f401f403f307),
    LL(0xc0cbcb40cbc016dd), LL(0xc63e3e423ec6edd3), LL(0x1105050f0511282d), LL(0xe66767a967e61f78),
    LL(0x53e4e431e4537397), LL(0xbb27276927bb2502), LL(0x584141c341583273), LL(0x9d8b8b808b9d2ca7),
    LL(0x01a7a7f4a70151f6), LL(0x947d7d877d94cfb2), LL(0xfb9595a295fbdc49), LL(0x9fd8d875d89f8e56),
    LL(0x30fbfb10fb308b70), LL(0x71eeee2fee7123cd), LL(0x917c7c847c91c7bb), LL(0xe36666aa66e31771),
    LL(0x8edddd7add8ea67b), LL(0x4b171739174bb8af), LL(0x464747c947460245), LL(0xdc9e9ebf9edc841a),
    LL(0xc5caca43cac51ed4), LL(0x992d2d772d997558), LL(0x79bfbfdcbf79912e), LL(0x1b070709071b383f),
    LL(0x23adadeaad2301ac), LL(0x2f5a5aee5a2feab0), LL(0xb583839883b56cef), LL(0xff33335533ff85b6),
    LL(0xf26363a563f23f5c), LL(0x0a020206020a1012), LL(0x38aaaae3aa383993), LL(0xa871719371a8afde),
    LL(0xcfc8c845c8cf0ec6), LL(0x7d19192b197dc8d1), LL(0x704949db4970723b), LL(0x9ad9d976d99a865f),
    LL(0x1df2f20bf21dc331), LL(0x48e3e338e3484ba8), LL(0x2a5b5bed5b2ae2b9), LL(0x92888885889234bc),
    LL(0xc89a9ab39ac8a43e), LL(0xbe26266a26be2d0b), LL(0xfa32325632fa8dbf), LL(0x4ab0b0cdb04ae959),
    LL(0x6ae9e926e96a1bf2), LL(0x330f0f110f337877), LL(0xa6d5d562d5a6e633), LL(0xba80809d80ba74f4),
    LL(0x7cbebedfbe7c9927), LL(0xdecdcd4acdde26eb), LL(0xe434345c34e4bd89), LL(0x754848d848757a32),
    LL(0x24ffff1cff24ab54), LL(0x8f7a7a8e7a8ff78d), LL(0xea9090ad90eaf464), LL(0x3e5f5fe15f3ec29d),
    LL(0xa020206020a01d3d), LL(0xd56868b868d5670f), LL(0x721a1a2e1a72d0ca), LL(0x2caeaeefae2c19b7),
    LL(0x5eb4b4c1b45ec97d), LL(0x195454fc54199ace), LL(0xe59393a893e5ec7f), LL(0xaa22226622aa0d2f),
    LL(0xe96464ac64e90763), LL(0x12f1f10ef112db2a), LL(0xa273739573a2bfcc), LL(0x5a121236125a9082),
    LL(0x5d4040c0405d3a7a), LL(0x2808081808284048), LL(0xe8c3c358c3e85695), LL(0x7becec29ec7b33df),
    LL(0x90dbdb70db90964d), LL(0x1fa1a1fea11f61c0), LL(0x838d8d8a8d831c91), LL(0xc93d3d473dc9f5c8),
    LL(0xf19797a497f1cc5b), LL(0x0000000000000000), LL(0xd4cfcf4ccfd436f9), LL(0x872b2b7d2b87456e),
    LL(0xb376769a76b397e1), LL(0xb082829b82b064e6), LL(0xa9d6d667d6a9fe28), LL(0x771b1b2d1b77d8c3),
    LL(0x5bb5b5c2b55bc174), LL(0x29afafecaf2911be), LL(0xdf6a6abe6adf771d), LL(0x0d5050f0500dbaea),
    LL(0x4c4545cf454c1257), LL(0x18f3f308f318cb38), LL(0xf030305030f09dad), LL(0x74efef2cef742bc4),
    LL(0xc33f3f413fc3e5da), LL(0x1c5555ff551c92c7), LL(0x10a2a2fba21079db), LL(0x65eaea23ea6503e9),
    LL(0xec6565af65ec0f6a), LL(0x68babad3ba68b903), LL(0x932f2f712f93654a), LL(0xe7c0c05dc0e74e8e),
    LL(0x81dede7fde81be60), LL(0x6c1c1c241c6ce0fc), LL(0x2efdfd1afd2ebb46), LL(0x644d4dd74d64521f),
    LL(0xe09292ab92e0e476), LL(0xbc75759f75bc8ffa), LL(0x1e06060a061e3036), LL(0x988a8a838a9824ae),
    LL(0x40b2b2cbb240f94b), LL(0x59e6e637e6596385), LL(0x360e0e120e36707e), LL(0x631f1f211f63f8e7),
    LL(0xf76262a662f73755), LL(0xa3d4d461d4a3ee3a), LL(0x32a8a8e5a8322981), LL(0xf49696a796f4c452),
    LL(0x3af9f916f93a9b62), LL(0xf6c5c552c5f666a3), LL(0xb125256f25b13510), LL(0x205959eb5920f2ab),
    LL(0xae84849184ae54d0), LL(0xa772729672a7b7c5), LL(0xdd39394b39ddd5ec), LL(0x614c4cd44c615a16),
    LL(0x3b5e5ee25e3bca94), LL(0x857878887885e79f), LL(0xd838384838d8dde5), LL(0x868c8c898c861498),
    LL(0xb2d1d16ed1b2c617), LL(0x0ba5a5f2a50b41e4), LL(0x4de2e23be24d43a1), LL(0xf86161a361f82f4e),
    LL(0x45b3b3c8b345f142), LL(0xa521216321a51534), LL(0xd69c9cb99cd69408), LL(0x661e1e221e66f0ee),
    LL(0x524343c543522261), LL(0xfcc7c754c7fc76b1), LL(0x2bfcfc19fc2bb34f), LL(0x1404040c04142024),
    LL(0x085151f35108b2e3), LL(0xc79999b699c7bc25), LL(0xc46d6db76dc44f22), LL(0x390d0d170d396865),
    LL(0x35fafa13fa358379), LL(0x84dfdf7cdf84b669), LL(0x9b7e7e827e9bd7a9), LL(0xb424246c24b43d19),
    LL(0xd73b3b4d3bd7c5fe), LL(0x3dababe0ab3d319a), LL(0xd1cece4fced13ef0), LL(0x5511113311558899),
    LL(0x898f8f8c8f890c83), LL(0x6b4e4ed24e6b4a04), LL(0x51b7b7c4b751d166), LL(0x60ebeb20eb600be0),
    LL(0xcc3c3c443cccfdc1), LL(0xbf81819e81bf7cfd), LL(0xfe9494a194fed440), LL(0x0cf7f704f70ceb1c),
    LL(0x67b9b9d6b967a118), LL(0x5f131335135f988b), LL(0x9c2c2c742c9c7d51), LL(0xb8d3d368d3b8d605),
    LL(0x5ce7e734e75c6b8c), LL(0xcb6e6eb26ecb5739), LL(0xf3c4c451c4f36eaa), LL(0x0f030305030f181b),
    LL(0x135656fa56138adc), LL(0x494444cc44491a5e), LL(0x9e7f7f817f9edfa0), LL(0x37a9a9e6a9372188),
    LL(0x822a2a7e2a824d67), LL(0x6dbbbbd0bb6db10a), LL(0xe2c1c15ec1e24687), LL(0x025353f55302a2f1),
    LL(0x8bdcdc79dc8bae72), LL(0x270b0b1d0b275853), LL(0xd39d9dba9dd39c01), LL(0xc16c6cb46cc1472b),
    LL(0xf531315331f595a4), LL(0xb974749c74b987f3), LL(0x09f6f607f609e315), LL(0x434646ca46430a4c),
    LL(0x26acace9ac2609a5), LL(0x9789898689973cb5), LL(0x4414143c1444a0b4), LL(0x42e1e13ee1425bba),
    LL(0x4e16163a164eb0a6), LL(0xd23a3a4e3ad2cdf7), LL(0xd06969bb69d06f06), LL(0x2d09091b092d4841),
    LL(0xad70709070ada7d7), LL(0x54b6b6c7b654d96f), LL(0xb7d0d06dd0b7ce1e), LL(0x7eeded2aed7e3bd6),
    LL(0xdbcccc49ccdb2ee2), LL(0x574242c642572a68), LL(0xc29898b598c2b42c), LL(0x0ea4a4f1a40e49ed),
    LL(0x8828287828885d75), LL(0x315c5ce45c31da86), LL(0x3ff8f815f83f936b), LL(0xa486869786a444c2),
};

static const u64 C2[256] = {
    LL(0xd8781818281878c0), LL(0x26af23236523af05), LL(0xb8f9c6c657c6f97e), LL(0xfb6fe8e825e86f13),
    LL(0xcba187879487a14c), LL(0x1162b8b8d5b862a9), LL(0x0905010103010508), LL(0x0d6e4f4fd14f6e42),
    LL(0x9bee36365a36eead), LL(0xff04a6a6f7a60459), LL(0x0cbdd2d26bd2bdde), LL(0x0e06f5f502f506fb),
    LL(0x968079798b7980ef), LL(0x30ce6f6fb16fce5f), LL(0x6def9191ae91effc), LL(0xf8075252f65207aa),
    LL(0x47fd6060a060fd27), LL(0x3576bcbcd9bc7689), LL(0x37cd9b9bb09bcdac), LL(0x8a8c8e8e8f8e8c04),
    LL(0xd215a3a3f8a31571), LL(0x6c3c0c0c140c3c60), LL(0x848a7b7b8d7b8aff), LL(0x80e135355f35e1b5),
    LL(0xf5691d1d271d69e8), LL(0xb347e0e03de04753), LL(0x21acd7d764d7acf6), LL(0x9cedc2c25bc2ed5e),
    LL(0x43962e2e722e966d), LL(0x297a4b4bdd4b7a62), LL(0x5d21fefe1ffe21a3), LL(0xd5165757f9571682),
    LL(0xbd4115153f1541a8), LL(0xe8b677779977b69f), LL(0x92eb37375937eba5), LL(0x9e56e5e532e5567b),
    LL(0x13d99f9fbc9fd98c), LL(0x2317f0f00df017d3), LL(0x207f4a4ade4a7f6a), LL(0x4495dada73da959e),
    LL(0xa2255858e85825fa), LL(0xcfcac9c946c9ca06), LL(0x7c8d29297b298d55), LL(0x5a220a0a1e0a2250),
    LL(0x504fb1b1ceb14fe1), LL(0xc91aa0a0fda01a69), LL(0x14da6b6bbd6bda7f), LL(0xd9ab85859285ab5c),
    LL(0x3c73bdbddabd7381), LL(0x8f345d5de75d34d2), LL(0x9050101030105080), LL(0x0703f4f401f403f3),
    LL(0xddc0cbcb40cbc016), LL(0xd3c63e3e423ec6ed), LL(0x2d1105050f051128), LL(0x78e66767a967e61f),
    LL(0x9753e4e431e45373), LL(0x02bb27276927bb25), LL(0x73584141c3415832), LL(0xa79d8b8b808b9d2c),
    LL(0xf601a7a7f4a70151), LL(0xb2947d7d877d94cf), LL(0x49fb9595a295fbdc), LL(0x569fd8d875d89f8e),
    LL(0x7030fbfb10fb308b), LL(0xcd71eeee2fee7123), LL(0xbb917c7c847c91c7), LL(0x71e36666aa66e317),
    LL(0x7b8edddd7add8ea6), LL(0xaf4b171739174bb8), LL(0x45464747c9474602), LL(0x1adc9e9ebf9edc84),
    LL(0xd4c5caca43cac51e), LL(0x58992d2d772d9975), LL(0x2e79bfbfdcbf7991), LL(0x3f1b070709071b38),
    LL(0xac23adadeaad2301), LL(0xb02f5a5aee5a2fea), LL(0xefb583839883b56c), LL(0xb6ff33335533ff85),
    LL(0x5cf26363a563f23f), LL(0x120a020206020a10), LL(0x9338aaaae3aa3839), LL(0xdea871719371a8af),
    LL(0xc6cfc8c845c8cf0e), LL(0xd17d19192b197dc8), LL(0x3b704949db497072), LL(0x5f9ad9d976d99a86),
    LL(0x311df2f20bf21dc3), LL(0xa848e3e338e3484b), LL(0xb92a5b5bed5b2ae2), LL(0xbc92888885889234),
    LL(0x3ec89a9ab39ac8a4), LL(0x0bbe26266a26be2d), LL(0xbffa32325632fa8d), LL(0x594ab0b0cdb04ae9),
    LL(0xf26ae9e926e96a1b), LL(0x77330f0f110f3378), LL(0x33a6d5d562d5a6e6), LL(0xf4ba80809d80ba74),
    LL(0x277cbebedfbe7c99), LL(0xebdecdcd4acdde26), LL(0x89e434345c34e4bd), LL(0x32754848d848757a),
    LL(0x5424ffff1cff24ab), LL(0x8d8f7a7a8e7a8ff7), LL(0x64ea9090ad90eaf4), LL(0x9d3e5f5fe15f3ec2),
    LL(0x3da020206020a01d), LL(0x0fd56868b868d567), LL(0xca721a1a2e1a72d0), LL(0xb72caeaeefae2c19),
    LL(0x7d5eb4b4c1b45ec9), LL(0xce195454fc54199a), LL(0x7fe59393a893e5ec), LL(0x2faa22226622aa0d),
    LL(0x63e96464ac64e907), LL(0x2a12f1f10ef112db), LL(0xcca273739573a2bf), LL(0x825a121236125a90),
    LL(0x7a5d4040c0405d3a), LL(0x4828080818082840), LL(0x95e8c3c358c3e856), LL(0xdf7becec29ec7b33),
    LL(0x4d90dbdb70db9096), LL(0xc01fa1a1fea11f61), LL(0x91838d8d8a8d831c), LL(0xc8c93d3d473dc9f5),
    LL(0x5bf19797a497f1cc), LL(0x0000000000000000), LL(0xf9d4cfcf4ccfd436), LL(0x6e872b2b7d2b8745),
    LL(0xe1b376769a76b397), LL(0xe6b082829b82b064), LL(0x28a9d6d667d6a9fe), LL(0xc3771b1b2d1b77d8),
    LL(0x745bb5b5c2b55bc1), LL(0xbe29afafecaf2911), LL(0x1ddf6a6abe6adf77), LL(0xea0d5050f0500dba),
    LL(0x574c4545cf454c12), LL(0x3818f3f308f318cb), LL(0xadf030305030f09d), LL(0xc474efef2cef742b),
    LL(0xdac33f3f413fc3e5), LL(0xc71c5555ff551c92), LL(0xdb10a2a2fba21079), LL(0xe965eaea23ea6503),
    LL(0x6aec6565af65ec0f), LL(0x0368babad3ba68b9), LL(0x4a932f2f712f9365), LL(0x8ee7c0c05dc0e74e),
    LL(0x6081dede7fde81be), LL(0xfc6c1c1c241c6ce0), LL(0x462efdfd1afd2ebb), LL(0x1f644d4dd74d6452),
    LL(0x76e09292ab92e0e4), LL(0xfabc75759f75bc8f), LL(0x361e06060a061e30), LL(0xae988a8a838a9824),
    LL(0x4b40b2b2cbb240f9), LL(0x8559e6e637e65963), LL(0x7e360e0e120e3670), LL(0xe7631f1f211f63f8),
    LL(0x55f76262a662f737), LL(0x3aa3d4d461d4a3ee), LL(0x8132a8a8e5a83229), LL(0x52f49696a796f4c4),
    LL(0x623af9f916f93a9b), LL(0xa3f6c5c552c5f666), LL(0x10b125256f25b135), LL(0xab205959eb5920f2),
    LL(0xd0ae84849184ae54), LL(0xc5a772729672a7b7), LL(0xecdd39394b39ddd5), LL(0x16614c4cd44c615a),
    LL(0x943b5e5ee25e3bca), LL(0x9f857878887885e7), LL(0xe5d838384838d8dd), LL(0x98868c8c898c8614),
    LL(0x17b2d1d16ed1b2c6), LL(0xe40ba5a5f2a50b41), LL(0xa14de2e23be24d43), LL(0x4ef86161a361f82f),
    LL(0x4245b3b3c8b345f1), LL(0x34a521216321a515), LL(0x08d69c9cb99cd694), LL(0xee661e1e221e66f0),
    LL(0x61524343c5435222), LL(0xb1fcc7c754c7fc76), LL(0x4f2bfcfc19fc2bb3), LL(0x241404040c041420),
    LL(0xe3085151f35108b2), LL(0x25c79999b699c7bc), LL(0x22c46d6db76dc44f), LL(0x65390d0d170d3968),
    LL(0x7935fafa13fa3583), LL(0x6984dfdf7cdf84b6), LL(0xa99b7e7e827e9bd7), LL(0x19b424246c24b43d),
    LL(0xfed73b3b4d3bd7c5), LL(0x9a3dababe0ab3d31), LL(0xf0d1cece4fced13e), LL(0x9955111133115588),
    LL(0x83898f8f8c8f890c), LL(0x046b4e4ed24e6b4a), LL(0x6651b7b7c4b751d1), LL(0xe060ebeb20eb600b),
    LL(0xc1cc3c3c443cccfd), LL(0xfdbf81819e81bf7c), LL(0x40fe9494a194fed4), LL(0x1c0cf7f704f70ceb),
    LL(0x1867b9b9d6b967a1), LL(0x8b5f131335135f98), LL(0x519c2c2c742c9c7d), LL(0x05b8d3d368d3b8d6),
    LL(0x8c5ce7e734e75c6b), LL(0x39cb6e6eb26ecb57), LL(0xaaf3c4c451c4f36e), LL(0x1b0f030305030f18),
    LL(0xdc135656fa56138a), LL(0x5e494444cc44491a), LL(0xa09e7f7f817f9edf), LL(0x8837a9a9e6a93721),
    LL(0x67822a2a7e2a824d), LL(0x0a6dbbbbd0bb6db1), LL(0x87e2c1c15ec1e246), LL(0xf1025353f55302a2),
    LL(0x728bdcdc79dc8bae), LL(0x53270b0b1d0b2758), LL(0x01d39d9dba9dd39c), LL(0x2bc16c6cb46cc147),
    LL(0xa4f531315331f595), LL(0xf3b974749c74b987), LL(0x1509f6f607f609e3), LL(0x4c434646ca46430a),
    LL(0xa526acace9ac2609), LL(0xb59789898689973c), LL(0xb44414143c1444a0), LL(0xba42e1e13ee1425b),
    LL(0xa64e16163a164eb0), LL(0xf7d23a3a4e3ad2cd), LL(0x06d06969bb69d06f), LL(0x412d09091b092d48),
    LL(0xd7ad70709070ada7), LL(0x6f54b6b6c7b654d9), LL(0x1eb7d0d06dd0b7ce), LL(0xd67eeded2aed7e3b),
    LL(0xe2dbcccc49ccdb2e), LL(0x68574242c642572a), LL(0x2cc29898b598c2b4), LL(0xed0ea4a4f1a40e49),
    LL(0x758828287828885d), LL(0x86315c5ce45c31da), LL(0x6b3ff8f815f83f93), LL(0xc2a486869786a444),
};

static const u64 C3[256] = {
    LL(0xc0d8781818281878), LL(0x0526af23236523af), LL(0x7eb8f9c6c657c6f9), LL(0x13fb6fe8e825e86f),
    LL(0x4ccba187879487a1), LL(0xa91162b8b8d5b862), LL(0x0809050101030105), LL(0x420d6e4f4fd14f6e),
    LL(0xad9bee36365a36ee), LL(0x59ff04a6a6f7a604), LL(0xde0cbdd2d26bd2bd), LL(0xfb0e06f5f502f506),
    LL(0xef968079798b7980), LL(0x5f30ce6f6fb16fce), LL(0xfc6def9191ae91ef), LL(0xaaf8075252f65207),
    LL(0x2747fd6060a060fd), LL(0x893576bcbcd9bc76), LL(0xac37cd9b9bb09bcd), LL(0x048a8c8e8e8f8e8c),
    LL(0x71d215a3a3f8a315), LL(0x606c3c0c0c140c3c), LL(0xff848a7b7b8d7b8a), LL(0xb580e135355f35e1),
    LL(0xe8f5691d1d271d69), LL(0x53b347e0e03de047), LL(0xf621acd7d764d7ac), LL(0x5e9cedc2c25bc2ed),
    LL(0x6d43962e2e722e96), LL(0x62297a4b4bdd4b7a), LL(0xa35d21fefe1ffe21), LL(0x82d5165757f95716),
    LL(0xa8bd4115153f1541), LL(0x9fe8b677779977b6), LL(0xa592eb37375937eb), LL(0x7b9e56e5e532e556),
    LL(0x8c13d99f9fbc9fd9), LL(0xd32317f0f00df017), LL(0x6a207f4a4ade4a7f), LL(0x9e4495dada73da95),
    LL(0xfaa2255858e85825), LL(0x06cfcac9c946c9ca), LL(0x557c8d29297b298d), LL(0x505a220a0a1e0a22),
    LL(0xe1504fb1b1ceb14f), LL(0x69c91aa0a0fda01a), LL(0x7f14da6b6bbd6bda), LL(0x5cd9ab85859285ab),
    LL(0x813c73bdbddabd73), LL(0xd28f345d5de75d34), LL(0x8090501010301050), LL(0xf30703f4f401f403),
    LL(0x16ddc0cbcb40cbc0), LL(0xedd3c63e3e423ec6), LL(0x282d1105050f0511), LL(0x1f78e66767a967e6),
    LL(0x739753e4e431e453), LL(0x2502bb27276927bb), LL(0x3273584141c34158), LL(0x2ca79d8b8b808b9d),
    LL(0x51f601a7a7f4a701), LL(0xcfb2947d7d877d94), LL(0xdc49fb9595a295fb), LL(0x8e569fd8d875d89f),
    LL(0x8b7030fbfb10fb30), LL(0x23cd71eeee2fee71), LL(0xc7bb917c7c847c91), LL(0x1771e36666aa66e3),
    LL(0xa67b8edddd7add8e), LL(0xb8af4b171739174b), LL(0x0245464747c94746), LL(0x841adc9e9ebf9edc),
    LL(0x1ed4c5caca43cac5), LL(0x7558992d2d772d99), LL(0x912e79bfbfdcbf79), LL(0x383f1b070709071b),
    LL(0x01ac23adadeaad23), LL(0xeab02f5a5aee5a2f), LL(0x6cefb583839883b5), LL(0x85b6ff33335533ff),
    LL(0x3f5cf26363a563f2), LL(0x10120a020206020a), LL(0x399338aaaae3aa38), LL(0xafdea871719371a8),
    LL(0x0ec6cfc8c845c8cf), LL(0xc8d17d19192b197d), LL(0x723b704949db4970), LL(0x865f9ad9d976d99a),
    LL(0xc3311df2f20bf21d), LL(0x4ba848e3e338e348), LL(0xe2b92a5b5bed5b2a), LL(0x34bc928888858892),
    LL(0xa43ec89a9ab39ac8), LL(0x2d0bbe26266a26be), LL(0x8dbffa32325632fa), LL(0xe9594ab0b0cdb04a),
    LL(0x1bf26ae9e926e96a), LL(0x7877330f0f110f33), LL(0xe633a6d5d562d5a6), LL(0x74f4ba80809d80ba),
    LL(0x99277cbebedfbe7c), LL(0x26ebdecdcd4acdde), LL(0xbd89e434345c34e4), LL(0x7a32754848d84875),
    LL(0xab5424ffff1cff24), LL(0xf78d8f7a7a8e7a8f), LL(0xf464ea9090ad90ea), LL(0xc29d3e5f5fe15f3e),
    LL(0x1d3da020206020a0), LL(0x670fd56868b868d5), LL(0xd0ca721a1a2e1a72), LL(0x19b72caeaeefae2c),
    LL(0xc97d5eb4b4c1b45e), LL(0x9ace195454fc5419), LL(0xec7fe59393a893e5), LL(0x0d2faa22226622aa),
    LL(0x0763e96464ac64e9), LL(0xdb2a12f1f10ef112), LL(0xbfcca273739573a2), LL(0x90825a121236125a),
    LL(0x3a7a5d4040c0405d), LL(0x4048280808180828), LL(0x5695e8c3c358c3e8), LL(0x33df7becec29ec7b),
    LL(0x964d90dbdb70db90), LL(0x61c01fa1a1fea11f), LL(0x1c91838d8d8a8d83), LL(0xf5c8c93d3d473dc9),
    LL(0xcc5bf19797a497f1), LL(0x0000000000000000), LL(0x36f9d4cfcf4ccfd4), LL(0x456e872b2b7d2b87),
    LL(0x97e1b376769a76b3), LL(0x64e6b082829b82b0), LL(0xfe28a9d6d667d6a9), LL(0xd8c3771b1b2d1b77),
    LL(0xc1745bb5b5c2b55b), LL(0x11be29afafecaf29), LL(0x771ddf6a6abe6adf), LL(0xbaea0d5050f0500d),
    LL(0x12574c4545cf454c), LL(0xcb3818f3f308f318), LL(0x9dadf030305030f0), LL(0x2bc474efef2cef74),
    LL(0xe5dac33f3f413fc3), LL(0x92c71c5555ff551c), LL(0x79db10a2a2fba210), LL(0x03e965eaea23ea65),
    LL(0x0f6aec6565af65ec), LL(0xb90368babad3ba68), LL(0x654a932f2f712f93), LL(0x4e8ee7c0c05dc0e7),
    LL(0xbe6081dede7fde81), LL(0xe0fc6c1c1c241c6c), LL(0xbb462efdfd1afd2e), LL(0x521f644d4dd74d64),
    LL(0xe476e09292ab92e0), LL(0x8ffabc75759f75bc), LL(0x30361e06060a061e), LL(0x24ae988a8a838a98),
    LL(0xf94b40b2b2cbb240), LL(0x638559e6e637e659), LL(0x707e360e0e120e36), LL(0xf8e7631f1f211f63),
    LL(0x3755f76262a662f7), LL(0xee3aa3d4d461d4a3), LL(0x298132a8a8e5a832), LL(0xc452f49696a796f4),
    LL(0x9b623af9f916f93a), LL(0x66a3f6c5c552c5f6), LL(0x3510b125256f25b1), LL(0xf2ab205959eb5920),
    LL(0x54d0ae84849184ae), LL(0xb7c5a772729672a7), LL(0xd5ecdd39394b39dd), LL(0x5a16614c4cd44c61),
    LL(0xca943b5e5ee25e3b), LL(0xe79f857878887885), LL(0xdde5d838384838d8), LL(0x1498868c8c898c86),
    LL(0xc617b2d1d16ed1b2), LL(0x41e40ba5a5f2a50b), LL(0x43a14de2e23be24d), LL(0x2f4ef86161a361f8),
    LL(0xf14245b3b3c8b345), LL(0x1534a521216321a5), LL(0x9408d69c9cb99cd6), LL(0xf0ee661e1e221e66),
    LL(0x2261524343c54352), LL(0x76b1fcc7c754c7fc), LL(0xb34f2bfcfc19fc2b), LL(0x20241404040c0414),
    LL(0xb2e3085151f35108), LL(0xbc25c79999b699c7), LL(0x4f22c46d6db76dc4), LL(0x6865390d0d170d39),
    LL(0x837935fafa13fa35), LL(0xb66984dfdf7cdf84), LL(0xd7a99b7e7e827e9b), LL(0x3d19b424246c24b4),
    LL(0xc5fed73b3b4d3bd7), LL(0x319a3dababe0ab3d), LL(0x3ef0d1cece4fced1), LL(0x8899551111331155),
    LL(0x0c83898f8f8c8f89), LL(0x4a046b4e4ed24e6b), LL(0xd16651b7b7c4b751), LL(0x0be060ebeb20eb60),
    LL(0xfdc1cc3c3c443ccc), LL(0x7cfdbf81819e81bf), LL(0xd440fe9494a194fe), LL(0xeb1c0cf7f704f70c),
    LL(0xa11867b9b9d6b967), LL(0x988b5f131335135f), LL(0x7d519c2c2c742c9c), LL(0xd605b8d3d368d3b8),
    LL(0x6b8c5ce7e734e75c), LL(0x5739cb6e6eb26ecb), LL(0x6eaaf3c4c451c4f3), LL(0x181b0f030305030f),
    LL(0x8adc135656fa5613), LL(0x1a5e494444cc4449), LL(0xdfa09e7f7f817f9e), LL(0x218837a9a9e6a937),
    LL(0x4d67822a2a7e2a82), LL(0xb10a6dbbbbd0bb6d), LL(0x4687e2c1c15ec1e2), LL(0xa2f1025353f55302),
    LL(0xae728bdcdc79dc8b), LL(0x5853270b0b1d0b27), LL(0x9c01d39d9dba9dd3), LL(0x472bc16c6cb46cc1),
    LL(0x95a4f531315331f5), LL(0x87f3b974749c74b9), LL(0xe31509f6f607f609), LL(0x0a4c434646ca4643),
    LL(0x09a526acace9ac26), LL(0x3cb5978989868997), LL(0xa0b44414143c1444), LL(0x5bba42e1e13ee142),
    LL(0xb0a64e16163a164e), LL(0xcdf7d23a3a4e3ad2), LL(0x6f06d06969bb69d0), LL(0x48412d09091b092d),
    LL(0xa7d7ad70709070ad), LL(0xd96f54b6b6c7b654), LL(0xce1eb7d0d06dd0b7), LL(0x3bd67eeded2aed7e),
    LL(0x2ee2dbcccc49ccdb), LL(0x2a68574242c64257), LL(0xb42cc29898b598c2), LL(0x49ed0ea4a4f1a40e),
    LL(0x5d75882828782888), LL(0xda86315c5ce45c31), LL(0x936b3ff8f815f83f), LL(0x44c2a486869786a4),
};

static const u64 C4[256] = {
    LL(0x78c0d87818182818), LL(0xaf0526af23236523), LL(0xf97eb8f9c6c657c6), LL(0x6f13fb6fe8e825e8),
    LL(0xa14ccba187879487), LL(0x62a91162b8b8d5b8), LL(0x0508090501010301), LL(0x6e420d6e4f4fd14f),
    LL(0xeead9bee36365a36), LL(0x0459ff04a6a6f7a6), LL(0xbdde0cbdd2d26bd2), LL(0x06fb0e06f5f502f5),
    LL(0x80ef968079798b79), LL(0xce5f30ce6f6fb16f), LL(0xeffc6def9191ae91), LL(0x07aaf8075252f652),
    LL(0xfd2747fd6060a060), LL(0x76893576bcbcd9bc), LL(0xcdac37cd9b9bb09b), LL(0x8c048a8c8e8e8f8e),
    LL(0x1571d215a3a3f8a3), LL(0x3c606c3c0c0c140c), LL(0x8aff848a7b7b8d7b), LL(0xe1b580e135355f35),
    LL(0x69e8f5691d1d271d), LL(0x4753b347e0e03de0), LL(0xacf621acd7d764d7), LL(0xed5e9cedc2c25bc2),
    LL(0x966d43962e2e722e), LL(0x7a62297a4b4bdd4b), LL(0x21a35d21fefe1ffe), LL(0x1682d5165757f957),
    LL(0x41a8bd4115153f15), LL(0xb69fe8b677779977), LL(0xeba592eb37375937), LL(0x567b9e56e5e532e5),
    LL(0xd98c13d99f9fbc9f), LL(0x17d32317f0f00df0), LL(0x7f6a207f4a4ade4a), LL(0x959e4495dada73da),
    LL(0x25faa2255858e858), LL(0xca06cfcac9c946c9), LL(0x8d557c8d29297b29), LL(0x22505a220a0a1e0a),
    LL(0x4fe1504fb1b1ceb1), LL(0x1a69c91aa0a0fda0), LL(0xda7f14da6b6bbd6b), LL(0xab5cd9ab85859285),
    LL(0x73813c73bdbddabd), LL(0x34d28f345d5de75d), LL(0x5080905010103010), LL(0x03f30703f4f401f4),
    LL(0xc016ddc0cbcb40cb), LL(0xc6edd3c63e3e423e), LL(0x11282d1105050f05), LL(0xe61f78e66767a967),
    LL(0x53739753e4e431e4), LL(0xbb2502bb27276927), LL(0x583273584141c341), LL(0x9d2ca79d8b8b808b),
    LL(0x0151f601a7a7f4a7), LL(0x94cfb2947d7d877d), LL(0xfbdc49fb9595a295), LL(0x9f8e569fd8d875d8),
    LL(0x308b7030fbfb10fb), LL(0x7123cd71eeee2fee), LL(0x91c7bb917c7c847c), LL(0xe31771e36666aa66),
    LL(0x8ea67b8edddd7add), LL(0x4bb8af4b17173917), LL(0x460245464747c947), LL(0xdc841adc9e9ebf9e),
    LL(0xc51ed4c5caca43ca), LL(0x997558992d2d772d), LL(0x79912e79bfbfdcbf), LL(0x1b383f1b07070907),
    LL(0x2301ac23adadeaad), LL(0x2feab02f5a5aee5a), LL(0xb56cefb583839883), LL(0xff85b6ff33335533),
    LL(0xf23f5cf26363a563), LL(0x0a10120a02020602), LL(0x38399338aaaae3aa), LL(0xa8afdea871719371),
    LL(0xcf0ec6cfc8c845c8), LL(0x7dc8d17d19192b19), LL(0x70723b704949db49), LL(0x9a865f9ad9d976d9),
    LL(0x1dc3311df2f20bf2), LL(0x484ba848e3e338e3), LL(0x2ae2b92a5b5bed5b), LL(0x9234bc9288888588),
    LL(0xc8a43ec89a9ab39a), LL(0xbe2d0bbe26266a26), LL(0xfa8dbffa32325632), LL(0x4ae9594ab0b0cdb0),
    LL(0x6a1bf26ae9e926e9), LL(0x337877330f0f110f), LL(0xa6e633a6d5d562d5), LL(0xba74f4ba80809d80),
    LL(0x7c99277cbebedfbe), LL(0xde26ebdecdcd4acd), LL(0xe4bd89e434345c34), LL(0x757a32754848d848),
    LL(0x24ab5424ffff1cff), LL(0x8ff78d8f7a7a8e7a), LL(0xeaf464ea9090ad90), LL(0x3ec29d3e5f5fe15f),
    LL(0xa01d3da020206020), LL(0xd5670fd56868b868), LL(0x72d0ca721a1a2e1a), LL(0x2c19b72caeaeefae),
    LL(0x5ec97d5eb4b4c1b4), LL(0x199ace195454fc54), LL(0xe5ec7fe59393a893), LL(0xaa0d2faa22226622),
    LL(0xe90763e96464ac64), LL(0x12db2a12f1f10ef1), LL(0xa2bfcca273739573), LL(0x5a90825a12123612),
    LL(0x5d3a7a5d4040c040), LL(0x2840482808081808), LL(0xe85695e8c3c358c3), LL(0x7b33df7becec29ec),
    LL(0x90964d90dbdb70db), LL(0x1f61c01fa1a1fea1), LL(0x831c91838d8d8a8d), LL(0xc9f5c8c93d3d473d),
    LL(0xf1cc5bf19797a497), LL(0x0000000000000000), LL(0xd436f9d4cfcf4ccf), LL(0x87456e872b2b7d2b),
    LL(0xb397e1b376769a76), LL(0xb064e6b082829b82), LL(0xa9fe28a9d6d667d6), LL(0x77d8c3771b1b2d1b),
    LL(0x5bc1745bb5b5c2b5), LL(0x2911be29afafecaf), LL(0xdf771ddf6a6abe6a), LL(0x0dbaea0d5050f050),
    LL(0x4c12574c4545cf45), LL(0x18cb3818f3f308f3), LL(0xf09dadf030305030), LL(0x742bc474efef2cef),
    LL(0xc3e5dac33f3f413f), LL(0x1c92c71c5555ff55), LL(0x1079db10a2a2fba2), LL(0x6503e965eaea23ea),
    LL(0xec0f6aec6565af65), LL(0x68b90368babad3ba), LL(0x93654a932f2f712f), LL(0xe74e8ee7c0c05dc0),
    LL(0x81be6081dede7fde), LL(0x6ce0fc6c1c1c241c), LL(0x2ebb462efdfd1afd), LL(0x64521f644d4dd74d),
    LL(0xe0e476e09292ab92), LL(0xbc8ffabc75759f75), LL(0x1e30361e06060a06), LL(0x9824ae988a8a838a),
    LL(0x40f94b40b2b2cbb2), LL(0x59638559e6e637e6), LL(0x36707e360e0e120e), LL(0x63f8e7631f1f211f),
    LL(0xf73755f76262a662), LL(0xa3ee3aa3d4d461d4), LL(0x32298132a8a8e5a8), LL(0xf4c452f49696a796),
    LL(0x3a9b623af9f916f9), LL(0xf666a3f6c5c552c5), LL(0xb13510b125256f25), LL(0x20f2ab205959eb59),
    LL(0xae54d0ae84849184), LL(0xa7b7c5a772729672), LL(0xddd5ecdd39394b39), LL(0x615a16614c4cd44c),
    LL(0x3bca943b5e5ee25e), LL(0x85e79f8578788878), LL(0xd8dde5d838384838), LL(0x861498868c8c898c),
    LL(0xb2c617b2d1d16ed1), LL(0x0b41e40ba5a5f2a5), LL(0x4d43a14de2e23be2), LL(0xf82f4ef86161a361),
    LL(0x45f14245b3b3c8b3), LL(0xa51534a521216321), LL(0xd69408d69c9cb99c), LL(0x66f0ee661e1e221e),
    LL(0x522261524343c543), LL(0xfc76b1fcc7c754c7), LL(0x2bb34f2bfcfc19fc), LL(0x1420241404040c04),
    LL(0x08b2e3085151f351), LL(0xc7bc25c79999b699), LL(0xc44f22c46d6db76d), LL(0x396865390d0d170d),
    LL(0x35837935fafa13fa), LL(0x84b66984dfdf7cdf), LL(0x9bd7a99b7e7e827e), LL(0xb43d19b424246c24),
    LL(0xd7c5fed73b3b4d3b), LL(0x3d319a3dababe0ab), LL(0xd13ef0d1cece4fce), LL(0x5588995511113311),
    LL(0x890c83898f8f8c8f), LL(0x6b4a046b4e4ed24e), LL(0x51d16651b7b7c4b7), LL(0x600be060ebeb20eb),
    LL(0xccfdc1cc3c3c443c), LL(0xbf7cfdbf81819e81), LL(0xfed440fe9494a194), LL(0x0ceb1c0cf7f704f7),
    LL(0x67a11867b9b9d6b9), LL(0x5f988b5f13133513), LL(0x9c7d519c2c2c742c), LL(0xb8d605b8d3d368d3),
    LL(0x5c6b8c5ce7e734e7), LL(0xcb5739cb6e6eb26e), LL(0xf36eaaf3c4c451c4), LL(0x0f181b0f03030503),
    LL(0x138adc135656fa56), LL(0x491a5e494444cc44), LL(0x9edfa09e7f7f817f), LL(0x37218837a9a9e6a9),
    LL(0x824d67822a2a7e2a), LL(0x6db10a6dbbbbd0bb), LL(0xe24687e2c1c15ec1), LL(0x02a2f1025353f553),
    LL(0x8bae728bdcdc79dc), LL(0x275853270b0b1d0b), LL(0xd39c01d39d9dba9d), LL(0xc1472bc16c6cb46c),
    LL(0xf595a4f531315331), LL(0xb987f3b974749c74), LL(0x09e31509f6f607f6), LL(0x430a4c434646ca46),
    LL(0x2609a526acace9ac), LL(0x973cb59789898689), LL(0x44a0b44414143c14), LL(0x425bba42e1e13ee1),
    LL(0x4eb0a64e16163a16), LL(0xd2cdf7d23a3a4e3a), LL(0xd06f06d06969bb69), LL(0x2d48412d09091b09),
    LL(0xada7d7ad70709070), LL(0x54d96f54b6b6c7b6), LL(0xb7ce1eb7d0d06dd0), LL(0x7e3bd67eeded2aed),
    LL(0xdb2ee2dbcccc49cc), LL(0x572a68574242c642), LL(0xc2b42cc29898b598), LL(0x0e49ed0ea4a4f1a4),
    LL(0x885d758828287828), LL(0x31da86315c5ce45c), LL(0x3f936b3ff8f815f8), LL(0xa444c2a486869786),
};

static const u64 C5[256] = {
    LL(0x1878c0d878181828), LL(0x23af0526af232365), LL(0xc6f97eb8f9c6c657), LL(0xe86f13fb6fe8e825),
    LL(0x87a14ccba1878794), LL(0xb862a91162b8b8d5), LL(0x0105080905010103), LL(0x4f6e420d6e4f4fd1),
    LL(0x36eead9bee36365a), LL(0xa60459ff04a6a6f7), LL(0xd2bdde0cbdd2d26b), LL(0xf506fb0e06f5f502),
    LL(0x7980ef968079798b), LL(0x6fce5f30ce6f6fb1), LL(0x91effc6def9191ae), LL(0x5207aaf8075252f6),
    LL(0x60fd2747fd6060a0), LL(0xbc76893576bcbcd9), LL(0x9bcdac37cd9b9bb0), LL(0x8e8c048a8c8e8e8f),
    LL(0xa31571d215a3a3f8), LL(0x0c3c606c3c0c0c14), LL(0x7b8aff848a7b7b8d), LL(0x35e1b580e135355f),
    LL(0x1d69e8f5691d1d27), LL(0xe04753b347e0e03d), LL(0xd7acf621acd7d764), LL(0xc2ed5e9cedc2c25b),
    LL(0x2e966d43962e2e72), LL(0x4b7a62297a4b4bdd), LL(0xfe21a35d21fefe1f), LL(0x571682d5165757f9),
    LL(0x1541a8bd4115153f), LL(0x77b69fe8b6777799), LL(0x37eba592eb373759), LL(0xe5567b9e56e5e532),
    LL(0x9fd98c13d99f9fbc), LL(0xf017d32317f0f00d), LL(0x4a7f6a207f4a4ade), LL(0xda959e4495dada73),
    LL(0x5825faa2255858e8), LL(0xc9ca06cfcac9c946), LL(0x298d557c8d29297b), LL(0x0a22505a220a0a1e),
    LL(0xb14fe1504fb1b1ce), LL(0xa01a69c91aa0a0fd), LL(0x6bda7f14da6b6bbd), LL(0x85ab5cd9ab858592),
    LL(0xbd73813c73bdbdda), LL(0x5d34d28f345d5de7), LL(0x1050809050101030), LL(0xf403f30703f4f401),
    LL(0xcbc016ddc0cbcb40), LL(0x3ec6edd3c63e3e42), LL(0x0511282d1105050f), LL(0x67e61f78e66767a9),
    LL(0xe453739753e4e431), LL(0x27bb2502bb272769), LL(0x41583273584141c3), LL(0x8b9d2ca79d8b8b80),
    LL(0xa70151f601a7a7f4), LL(0x7d94cfb2947d7d87), LL(0x95fbdc49fb9595a2), LL(0xd89f8e569fd8d875),
    LL(0xfb308b7030fbfb10), LL(0xee7123cd71eeee2f), LL(0x7c91c7bb917c7c84), LL(0x66e31771e36666aa),
    LL(0xdd8ea67b8edddd7a), LL(0x174bb8af4b171739), LL(0x47460245464747c9), LL(0x9edc841adc9e9ebf),
    LL(0xcac51ed4c5caca43), LL(0x2d997558992d2d77), LL(0xbf79912e79bfbfdc), LL(0x071b383f1b070709),
    LL(0xad2301ac23adadea), LL(0x5a2feab02f5a5aee), LL(0x83b56cefb5838398), LL(0x33ff85b6ff333355),
    LL(0x63f23f5cf26363a5), LL(0x020a10120a020206), LL(0xaa38399338aaaae3), LL(0x71a8afdea8717193),
    LL(0xc8cf0ec6cfc8c845), LL(0x197dc8d17d19192b), LL(0x4970723b704949db), LL(0xd99a865f9ad9d976),
    LL(0xf21dc3311df2f20b), LL(0xe3484ba848e3e338), LL(0x5b2ae2b92a5b5bed), LL(0x889234bc92888885),
    LL(0x9ac8a43ec89a9ab3), LL(0x26be2d0bbe26266a), LL(0x32fa8dbffa323256), LL(0xb04ae9594ab0b0cd),
    LL(0xe96a1bf26ae9e926), LL(0x0f337877330f0f11), LL(0xd5a6e633a6d5d562), LL(0x80ba74f4ba80809d),
    LL(0xbe7c99277cbebedf), LL(0xcdde26ebdecdcd4a), LL(0x34e4bd89e434345c), LL(0x48757a32754848d8),
    LL(0xff24ab5424ffff1c), LL(0x7a8ff78d8f7a7a8e), LL(0x90eaf464ea9090ad), LL(0x5f3ec29d3e5f5fe1),
    LL(0x20a01d3da0202060), LL(0x68d5670fd56868b8), LL(0x1a72d0ca721a1a2e), LL(0xae2c19b72caeaeef),
    LL(0xb45ec97d5eb4b4c1), LL(0x54199ace195454fc), LL(0x93e5ec7fe59393a8), LL(0x22aa0d2faa222266),
    LL(0x64e90763e96464ac), LL(0xf112db2a12f1f10e), LL(0x73a2bfcca2737395), LL(0x125a90825a121236),
    LL(0x405d3a7a5d4040c0), LL(0x0828404828080818), LL(0xc3e85695e8c3c358), LL(0xec7b33df7becec29),
    LL(0xdb90964d90dbdb70), LL(0xa11f61c01fa1a1fe), LL(0x8d831c91838d8d8a), LL(0x3dc9f5c8c93d3d47),
    LL(0x97f1cc5bf19797a4), LL(0x0000000000000000), LL(0xcfd436f9d4cfcf4c), LL(0x2b87456e872b2b7d),
    LL(0x76b397e1b376769a), LL(0x82b064e6b082829b), LL(0xd6a9fe28a9d6d667), LL(0x1b77d8c3771b1b2d),
    LL(0xb55bc1745bb5b5c2), LL(0xaf2911be29afafec), LL(0x6adf771ddf6a6abe), LL(0x500dbaea0d5050f0),
    LL(0x454c12574c4545cf), LL(0xf318cb3818f3f308), LL(0x30f09dadf0303050), LL(0xef742bc474efef2c),
    LL(0x3fc3e5dac33f3f41), LL(0x551c92c71c5555ff), LL(0xa21079db10a2a2fb), LL(0xea6503e965eaea23),
    LL(0x65ec0f6aec6565af), LL(0xba68b90368babad3), LL(0x2f93654a932f2f71), LL(0xc0e74e8ee7c0c05d),
    LL(0xde81be6081dede7f), LL(0x1c6ce0fc6c1c1c24), LL(0xfd2ebb462efdfd1a), LL(0x4d64521f644d4dd7),
    LL(0x92e0e476e09292ab), LL(0x75bc8ffabc75759f), LL(0x061e30361e06060a), LL(0x8a9824ae988a8a83),
    LL(0xb240f94b40b2b2cb), LL(0xe659638559e6e637), LL(0x0e36707e360e0e12), LL(0x1f63f8e7631f1f21),
    LL(0x62f73755f76262a6), LL(0xd4a3ee3aa3d4d461), LL(0xa832298132a8a8e5), LL(0x96f4c452f49696a7),
    LL(0xf93a9b623af9f916), LL(0xc5f666a3f6c5c552), LL(0x25b13510b125256f), LL(0x5920f2ab205959eb),
    LL(0x84ae54d0ae848491), LL(0x72a7b7c5a7727296), LL(0x39ddd5ecdd39394b), LL(0x4c615a16614c4cd4),
    LL(0x5e3bca943b5e5ee2), LL(0x7885e79f85787888), LL(0x38d8dde5d8383848), LL(0x8c861498868c8c89),
    LL(0xd1b2c617b2d1d16e), LL(0xa50b41e40ba5a5f2), LL(0xe24d43a14de2e23b), LL(0x61f82f4ef86161a3),
    LL(0xb345f14245b3b3c8), LL(0x21a51534a5212163), LL(0x9cd69408d69c9cb9), LL(0x1e66f0ee661e1e22),
    LL(0x43522261524343c5), LL(0xc7fc76b1fcc7c754), LL(0xfc2bb34f2bfcfc19), LL(0x041420241404040c),
    LL(0x5108b2e3085151f3), LL(0x99c7bc25c79999b6), LL(0x6dc44f22c46d6db7), LL(0x0d396865390d0d17),
    LL(0xfa35837935fafa13), LL(0xdf84b66984dfdf7c), LL(0x7e9bd7a99b7e7e82), LL(0x24b43d19b424246c),
    LL(0x3bd7c5fed73b3b4d), LL(0xab3d319a3dababe0), LL(0xced13ef0d1cece4f), LL(0x1155889955111133),
    LL(0x8f890c83898f8f8c), LL(0x4e6b4a046b4e4ed2), LL(0xb751d16651b7b7c4), LL(0xeb600be060ebeb20),
    LL(0x3cccfdc1cc3c3c44), LL(0x81bf7cfdbf81819e), LL(0x94fed440fe9494a1), LL(0xf70ceb1c0cf7f704),
    LL(0xb967a11867b9b9d6), LL(0x135f988b5f131335), LL(0x2c9c7d519c2c2c74), LL(0xd3b8d605b8d3d368),
    LL(0xe75c6b8c5ce7e734), LL(0x6ecb5739cb6e6eb2), LL(0xc4f36eaaf3c4c451), LL(0x030f181b0f030305),
    LL(0x56138adc135656fa), LL(0x44491a5e494444cc), LL(0x7f9edfa09e7f7f81), LL(0xa937218837a9a9e6),
    LL(0x2a824d67822a2a7e), LL(0xbb6db10a6dbbbbd0), LL(0xc1e24687e2c1c15e), LL(0x5302a2f1025353f5),
    LL(0xdc8bae728bdcdc79), LL(0x0b275853270b0b1d), LL(0x9dd39c01d39d9dba), LL(0x6cc1472bc16c6cb4),
    LL(0x31f595a4f5313153), LL(0x74b987f3b974749c), LL(0xf609e31509f6f607), LL(0x46430a4c434646ca),
    LL(0xac2609a526acace9), LL(0x89973cb597898986), LL(0x1444a0b44414143c), LL(0xe1425bba42e1e13e),
    LL(0x164eb0a64e16163a), LL(0x3ad2cdf7d23a3a4e), LL(0x69d06f06d06969bb), LL(0x092d48412d09091b),
    LL(0x70ada7d7ad707090), LL(0xb654d96f54b6b6c7), LL(0xd0b7ce1eb7d0d06d), LL(0xed7e3bd67eeded2a),
    LL(0xccdb2ee2dbcccc49), LL(0x42572a68574242c6), LL(0x98c2b42cc29898b5), LL(0xa40e49ed0ea4a4f1),
    LL(0x28885d7588282878), LL(0x5c31da86315c5ce4), LL(0xf83f936b3ff8f815), LL(0x86a444c2a4868697),
};

static const u64 C6[256] = {
    LL(0x281878c0d8781818), LL(0x6523af0526af2323), LL(0x57c6f97eb8f9c6c6), LL(0x25e86f13fb6fe8e8),
    LL(0x9487a14ccba18787), LL(0xd5b862a91162b8b8), LL(0x0301050809050101), LL(0xd14f6e420d6e4f4f),
    LL(0x5a36eead9bee3636), LL(0xf7a60459ff04a6a6), LL(0x6bd2bdde0cbdd2d2), LL(0x02f506fb0e06f5f5),
    LL(0x8b7980ef96807979), LL(0xb16fce5f30ce6f6f), LL(0xae91effc6def9191), LL(0xf65207aaf8075252),
    LL(0xa060fd2747fd6060), LL(0xd9bc76893576bcbc), LL(0xb09bcdac37cd9b9b), LL(0x8f8e8c048a8c8e8e),
    LL(0xf8a31571d215a3a3), LL(0x140c3c606c3c0c0c), LL(0x8d7b8aff848a7b7b), LL(0x5f35e1b580e13535),
    LL(0x271d69e8f5691d1d), LL(0x3de04753b347e0e0), LL(0x64d7acf621acd7d7), LL(0x5bc2ed5e9cedc2c2),
    LL(0x722e966d43962e2e), LL(0xdd4b7a62297a4b4b), LL(0x1ffe21a35d21fefe), LL(0xf9571682d5165757),
    LL(0x3f1541a8bd411515), LL(0x9977b69fe8b67777), LL(0x5937eba592eb3737), LL(0x32e5567b9e56e5e5),
    LL(0xbc9fd98c13d99f9f), LL(0x0df017d32317f0f0), LL(0xde4a7f6a207f4a4a), LL(0x73da959e4495dada),
    LL(0xe85825faa2255858), LL(0x46c9ca06cfcac9c9), LL(0x7b298d557c8d2929), LL(0x1e0a22505a220a0a),
    LL(0xceb14fe1504fb1b1), LL(0xfda01a69c91aa0a0), LL(0xbd6bda7f14da6b6b), LL(0x9285ab5cd9ab8585),
    LL(0xdabd73813c73bdbd), LL(0xe75d34d28f345d5d), LL(0x3010508090501010), LL(0x01f403f30703f4f4),
    LL(0x40cbc016ddc0cbcb), LL(0x423ec6edd3c63e3e), LL(0x0f0511282d110505), LL(0xa967e61f78e66767),
    LL(0x31e453739753e4e4), LL(0x6927bb2502bb2727), LL(0xc341583273584141), LL(0x808b9d2ca79d8b8b),
    LL(0xf4a70151f601a7a7), LL(0x877d94cfb2947d7d), LL(0xa295fbdc49fb9595), LL(0x75d89f8e569fd8d8),
    LL(0x10fb308b7030fbfb), LL(0x2fee7123cd71eeee), LL(0x847c91c7bb917c7c), LL(0xaa66e31771e36666),
    LL(0x7add8ea67b8edddd), LL(0x39174bb8af4b1717), LL(0xc947460245464747), LL(0xbf9edc841adc9e9e),
    LL(0x43cac51ed4c5caca), LL(0x772d997558992d2d), LL(0xdcbf79912e79bfbf), LL(0x09071b383f1b0707),
    LL(0xeaad2301ac23adad), LL(0xee5a2feab02f5a5a), LL(0x9883b56cefb58383), LL(0x5533ff85b6ff3333),
    LL(0xa563f23f5cf26363), LL(0x06020a10120a0202), LL(0xe3aa38399338aaaa), LL(0x9371a8afdea87171),
    LL(0x45c8cf0ec6cfc8c8), LL(0x2b197dc8d17d1919), LL(0xdb4970723b704949), LL(0x76d99a865f9ad9d9),
    LL(0x0bf21dc3311df2f2), LL(0x38e3484ba848e3e3), LL(0xed5b2ae2b92a5b5b), LL(0x85889234bc928888),
    LL(0xb39ac8a43ec89a9a), LL(0x6a26be2d0bbe2626), LL(0x5632fa8dbffa3232), LL(0xcdb04ae9594ab0b0),
    LL(0x26e96a1bf26ae9e9), LL(0x110f337877330f0f), LL(0x62d5a6e633a6d5d5), LL(0x9d80ba74f4ba8080),
    LL(0xdfbe7c99277cbebe), LL(0x4acdde26ebdecdcd), LL(0x5c34e4bd89e43434), LL(0xd848757a32754848),
    LL(0x1cff24ab5424ffff), LL(0x8e7a8ff78d8f7a7a), LL(0xad90eaf464ea9090), LL(0xe15f3ec29d3e5f5f),
    LL(0x6020a01d3da02020), LL(0xb868d5670fd56868), LL(0x2e1a72d0ca721a1a), LL(0xefae2c19b72caeae),
    LL(0xc1b45ec97d5eb4b4), LL(0xfc54199ace195454), LL(0xa893e5ec7fe59393), LL(0x6622aa0d2faa2222),
    LL(0xac64e90763e96464), LL(0x0ef112db2a12f1f1), LL(0x9573a2bfcca27373), LL(0x36125a90825a1212),
    LL(0xc0405d3a7a5d4040), LL(0x1808284048280808), LL(0x58c3e85695e8c3c3), LL(0x29ec7b33df7becec),
    LL(0x70db90964d90dbdb), LL(0xfea11f61c01fa1a1), LL(0x8a8d831c91838d8d), LL(0x473dc9f5c8c93d3d),
    LL(0xa497f1cc5bf19797), LL(0x0000000000000000), LL(0x4ccfd436f9d4cfcf), LL(0x7d2b87456e872b2b),
    LL(0x9a76b397e1b37676), LL(0x9b82b064e6b08282), LL(0x67d6a9fe28a9d6d6), LL(0x2d1b77d8c3771b1b),
    LL(0xc2b55bc1745bb5b5), LL(0xecaf2911be29afaf), LL(0xbe6adf771ddf6a6a), LL(0xf0500dbaea0d5050),
    LL(0xcf454c12574c4545), LL(0x08f318cb3818f3f3), LL(0x5030f09dadf03030), LL(0x2cef742bc474efef),
    LL(0x413fc3e5dac33f3f), LL(0xff551c92c71c5555), LL(0xfba21079db10a2a2), LL(0x23ea6503e965eaea),
    LL(0xaf65ec0f6aec6565), LL(0xd3ba68b90368baba), LL(0x712f93654a932f2f), LL(0x5dc0e74e8ee7c0c0),
    LL(0x7fde81be6081dede), LL(0x241c6ce0fc6c1c1c), LL(0x1afd2ebb462efdfd), LL(0xd74d64521f644d4d),
    LL(0xab92e0e476e09292), LL(0x9f75bc8ffabc7575), LL(0x0a061e30361e0606), LL(0x838a9824ae988a8a),
    LL(0xcbb240f94b40b2b2), LL(0x37e659638559e6e6), LL(0x120e36707e360e0e), LL(0x211f63f8e7631f1f),
    LL(0xa662f73755f76262), LL(0x61d4a3ee3aa3d4d4), LL(0xe5a832298132a8a8), LL(0xa796f4c452f49696),
    LL(0x16f93a9b623af9f9), LL(0x52c5f666a3f6c5c5), LL(0x6f25b13510b12525), LL(0xeb5920f2ab205959),
    LL(0x9184ae54d0ae8484), LL(0x9672a7b7c5a77272), LL(0x4b39ddd5ecdd3939), LL(0xd44c615a16614c4c),
    LL(0xe25e3bca943b5e5e), LL(0x887885e79f857878), LL(0x4838d8dde5d83838), LL(0x898c861498868c8c),
    LL(0x6ed1b2c617b2d1d1), LL(0xf2a50b41e40ba5a5), LL(0x3be24d43a14de2e2), LL(0xa361f82f4ef86161),
    LL(0xc8b345f14245b3b3), LL(0x6321a51534a52121), LL(0xb99cd69408d69c9c), LL(0x221e66f0ee661e1e),
    LL(0xc543522261524343), LL(0x54c7fc76b1fcc7c7), LL(0x19fc2bb34f2bfcfc), LL(0x0c04142024140404),
    LL(0xf35108b2e3085151), LL(0xb699c7bc25c79999), LL(0xb76dc44f22c46d6d), LL(0x170d396865390d0d),
    LL(0x13fa35837935fafa), LL(0x7cdf84b66984dfdf), LL(0x827e9bd7a99b7e7e), LL(0x6c24b43d19b42424),
    LL(0x4d3bd7c5fed73b3b), LL(0xe0ab3d319a3dabab), LL(0x4fced13ef0d1cece), LL(0x3311558899551111),
    LL(0x8c8f890c83898f8f), LL(0xd24e6b4a046b4e4e), LL(0xc4b751d16651b7b7), LL(0x20eb600be060ebeb),
    LL(0x443cccfdc1cc3c3c), LL(0x9e81bf7cfdbf8181), LL(0xa194fed440fe9494), LL(0x04f70ceb1c0cf7f7),
    LL(0xd6b967a11867b9b9), LL(0x35135f988b5f1313), LL(0x742c9c7d519c2c2c), LL(0x68d3b8d605b8d3d3),
    LL(0x34e75c6b8c5ce7e7), LL(0xb26ecb5739cb6e6e), LL(0x51c4f36eaaf3c4c4), LL(0x05030f181b0f0303),
    LL(0xfa56138adc135656), LL(0xcc44491a5e494444), LL(0x817f9edfa09e7f7f), LL(0xe6a937218837a9a9),
    LL(0x7e2a824d67822a2a), LL(0xd0bb6db10a6dbbbb), LL(0x5ec1e24687e2c1c1), LL(0xf55302a2f1025353),
    LL(0x79dc8bae728bdcdc), LL(0x1d0b275853270b0b), LL(0xba9dd39c01d39d9d), LL(0xb46cc1472bc16c6c),
    LL(0x5331f595a4f53131), LL(0x9c74b987f3b97474), LL(0x07f609e31509f6f6), LL(0xca46430a4c434646),
    LL(0xe9ac2609a526acac), LL(0x8689973cb5978989), LL(0x3c1444a0b4441414), LL(0x3ee1425bba42e1e1),
    LL(0x3a164eb0a64e1616), LL(0x4e3ad2cdf7d23a3a), LL(0xbb69d06f06d06969), LL(0x1b092d48412d0909),
    LL(0x9070ada7d7ad7070), LL(0xc7b654d96f54b6b6), LL(0x6dd0b7ce1eb7d0d0), LL(0x2aed7e3bd67eeded),
    LL(0x49ccdb2ee2dbcccc), LL(0xc642572a68574242), LL(0xb598c2b42cc29898), LL(0xf1a40e49ed0ea4a4),
    LL(0x7828885d75882828), LL(0xe45c31da86315c5c), LL(0x15f83f936b3ff8f8), LL(0x9786a444c2a48686),
};

static const u64 C7[256] = {
    LL(0x18281878c0d87818), LL(0x236523af0526af23), LL(0xc657c6f97eb8f9c6), LL(0xe825e86f13fb6fe8),
    LL(0x879487a14ccba187), LL(0xb8d5b862a91162b8), LL(0x0103010508090501), LL(0x4fd14f6e420d6e4f),
    LL(0x365a36eead9bee36), LL(0xa6f7a60459ff04a6), LL(0xd26bd2bdde0cbdd2), LL(0xf502f506fb0e06f5),
    LL(0x798b7980ef968079), LL(0x6fb16fce5f30ce6f), LL(0x91ae91effc6def91), LL(0x52f65207aaf80752),
    LL(0x60a060fd2747fd60), LL(0xbcd9bc76893576bc), LL(0x9bb09bcdac37cd9b), LL(0x8e8f8e8c048a8c8e),
    LL(0xa3f8a31571d215a3), LL(0x0c140c3c606c3c0c), LL(0x7b8d7b8aff848a7b), LL(0x355f35e1b580e135),
    LL(0x1d271d69e8f5691d), LL(0xe03de04753b347e0), LL(0xd764d7acf621acd7), LL(0xc25bc2ed5e9cedc2),
    LL(0x2e722e966d43962e), LL(0x4bdd4b7a62297a4b), LL(0xfe1ffe21a35d21fe), LL(0x57f9571682d51657),
    LL(0x153f1541a8bd4115), LL(0x779977b69fe8b677), LL(0x375937eba592eb37), LL(0xe532e5567b9e56e5),
    LL(0x9fbc9fd98c13d99f), LL(0xf00df017d32317f0), LL(0x4ade4a7f6a207f4a), LL(0xda73da959e4495da),
    LL(0x58e85825faa22558), LL(0xc946c9ca06cfcac9), LL(0x297b298d557c8d29), LL(0x0a1e0a22505a220a),
    LL(0xb1ceb14fe1504fb1), LL(0xa0fda01a69c91aa0), LL(0x6bbd6bda7f14da6b), LL(0x859285ab5cd9ab85),
    LL(0xbddabd73813c73bd), LL(0x5de75d34d28f345d), LL(0x1030105080905010), LL(0xf401f403f30703f4),
    LL(0xcb40cbc016ddc0cb), LL(0x3e423ec6edd3c63e), LL(0x050f0511282d1105), LL(0x67a967e61f78e667),
    LL(0xe431e453739753e4), LL(0x276927bb2502bb27), LL(0x41c3415832735841), LL(0x8b808b9d2ca79d8b),
    LL(0xa7f4a70151f601a7), LL(0x7d877d94cfb2947d), LL(0x95a295fbdc49fb95), LL(0xd875d89f8e569fd8),
    LL(0xfb10fb308b7030fb), LL(0xee2fee7123cd71ee), LL(0x7c847c91c7bb917c), LL(0x66aa66e31771e366),
    LL(0xdd7add8ea67b8edd), LL(0x1739174bb8af4b17), LL(0x47c9474602454647), LL(0x9ebf9edc841adc9e),
    LL(0xca43cac51ed4c5ca), LL(0x2d772d997558992d), LL(0xbfdcbf79912e79bf), LL(0x0709071b383f1b07),
    LL(0xadeaad2301ac23ad), LL(0x5aee5a2feab02f5a), LL(0x839883b56cefb583), LL(0x335533ff85b6ff33),
    LL(0x63a563f23f5cf263), LL(0x0206020a10120a02), LL(0xaae3aa38399338aa), LL(0x719371a8afdea871),
    LL(0xc845c8cf0ec6cfc8), LL(0x192b197dc8d17d19), LL(0x49db4970723b7049), LL(0xd976d99a865f9ad9),
    LL(0xf20bf21dc3311df2), LL(0xe338e3484ba848e3), LL(0x5bed5b2ae2b92a5b), LL(0x8885889234bc9288),
    LL(0x9ab39ac8a43ec89a), LL(0x266a26be2d0bbe26), LL(0x325632fa8dbffa32), LL(0xb0cdb04ae9594ab0),
    LL(0xe926e96a1bf26ae9), LL(0x0f110f337877330f), LL(0xd562d5a6e633a6d5), LL(0x809d80ba74f4ba80),
    LL(0xbedfbe7c99277cbe), LL(0xcd4acdde26ebdecd), LL(0x345c34e4bd89e434), LL(0x48d848757a327548),
    LL(0xff1cff24ab5424ff), LL(0x7a8e7a8ff78d8f7a), LL(0x90ad90eaf464ea90), LL(0x5fe15f3ec29d3e5f),
    LL(0x206020a01d3da020), LL(0x68b868d5670fd568), LL(0x1a2e1a72d0ca721a), LL(0xaeefae2c19b72cae),
    LL(0xb4c1b45ec97d5eb4), LL(0x54fc54199ace1954), LL(0x93a893e5ec7fe593), LL(0x226622aa0d2faa22),
    LL(0x64ac64e90763e964), LL(0xf10ef112db2a12f1), LL(0x739573a2bfcca273), LL(0x1236125a90825a12),
    LL(0x40c0405d3a7a5d40), LL(0x0818082840482808), LL(0xc358c3e85695e8c3), LL(0xec29ec7b33df7bec),
    LL(0xdb70db90964d90db), LL(0xa1fea11f61c01fa1), LL(0x8d8a8d831c91838d), LL(0x3d473dc9f5c8c93d),
    LL(0x97a497f1cc5bf197), LL(0x0000000000000000), LL(0xcf4ccfd436f9d4cf), LL(0x2b7d2b87456e872b),
    LL(0x769a76b397e1b376), LL(0x829b82b064e6b082), LL(0xd667d6a9fe28a9d6), LL(0x1b2d1b77d8c3771b),
    LL(0xb5c2b55bc1745bb5), LL(0xafecaf2911be29af), LL(0x6abe6adf771ddf6a), LL(0x50f0500dbaea0d50),
    LL(0x45cf454c12574c45), LL(0xf308f318cb3818f3), LL(0x305030f09dadf030), LL(0xef2cef742bc474ef),
    LL(0x3f413fc3e5dac33f), LL(0x55ff551c92c71c55), LL(0xa2fba21079db10a2), LL(0xea23ea6503e965ea),
    LL(0x65af65ec0f6aec65), LL(0xbad3ba68b90368ba), LL(0x2f712f93654a932f), LL(0xc05dc0e74e8ee7c0),
    LL(0xde7fde81be6081de), LL(0x1c241c6ce0fc6c1c), LL(0xfd1afd2ebb462efd), LL(0x4dd74d64521f644d),
    LL(0x92ab92e0e476e092), LL(0x759f75bc8ffabc75), LL(0x060a061e30361e06), LL(0x8a838a9824ae988a),
    LL(0xb2cbb240f94b40b2), LL(0xe637e659638559e6), LL(0x0e120e36707e360e), LL(0x1f211f63f8e7631f),
    LL(0x62a662f73755f762), LL(0xd461d4a3ee3aa3d4), LL(0xa8e5a832298132a8), LL(0x96a796f4c452f496),
    LL(0xf916f93a9b623af9), LL(0xc552c5f666a3f6c5), LL(0x256f25b13510b125), LL(0x59eb5920f2ab2059),
    LL(0x849184ae54d0ae84), LL(0x729672a7b7c5a772), LL(0x394b39ddd5ecdd39), LL(0x4cd44c615a16614c),
    LL(0x5ee25e3bca943b5e), LL(0x78887885e79f8578), LL(0x384838d8dde5d838), LL(0x8c898c861498868c),
    LL(0xd16ed1b2c617b2d1), LL(0xa5f2a50b41e40ba5), LL(0xe23be24d43a14de2), LL(0x61a361f82f4ef861),
    LL(0xb3c8b345f14245b3), LL(0x216321a51534a521), LL(0x9cb99cd69408d69c), LL(0x1e221e66f0ee661e),
    LL(0x43c5435222615243), LL(0xc754c7fc76b1fcc7), LL(0xfc19fc2bb34f2bfc), LL(0x040c041420241404),
    LL(0x51f35108b2e30851), LL(0x99b699c7bc25c799), LL(0x6db76dc44f22c46d), LL(0x0d170d396865390d),
    LL(0xfa13fa35837935fa), LL(0xdf7cdf84b66984df), LL(0x7e827e9bd7a99b7e), LL(0x246c24b43d19b424),
    LL(0x3b4d3bd7c5fed73b), LL(0xabe0ab3d319a3dab), LL(0xce4fced13ef0d1ce), LL(0x1133115588995511),
    LL(0x8f8c8f890c83898f), LL(0x4ed24e6b4a046b4e), LL(0xb7c4b751d16651b7), LL(0xeb20eb600be060eb),
    LL(0x3c443cccfdc1cc3c), LL(0x819e81bf7cfdbf81), LL(0x94a194fed440fe94), LL(0xf704f70ceb1c0cf7),
    LL(0xb9d6b967a11867b9), LL(0x1335135f988b5f13), LL(0x2c742c9c7d519c2c), LL(0xd368d3b8d605b8d3),
    LL(0xe734e75c6b8c5ce7), LL(0x6eb26ecb5739cb6e), LL(0xc451c4f36eaaf3c4), LL(0x0305030f181b0f03),
    LL(0x56fa56138adc1356), LL(0x44cc44491a5e4944), LL(0x7f817f9edfa09e7f), LL(0xa9e6a937218837a9),
    LL(0x2a7e2a824d67822a), LL(0xbbd0bb6db10a6dbb), LL(0xc15ec1e24687e2c1), LL(0x53f55302a2f10253),
    LL(0xdc79dc8bae728bdc), LL(0x0b1d0b275853270b), LL(0x9dba9dd39c01d39d), LL(0x6cb46cc1472bc16c),
    LL(0x315331f595a4f531), LL(0x749c74b987f3b974), LL(0xf607f609e31509f6), LL(0x46ca46430a4c4346),
    LL(0xace9ac2609a526ac), LL(0x898689973cb59789), LL(0x143c1444a0b44414), LL(0xe13ee1425bba42e1),
    LL(0x163a164eb0a64e16), LL(0x3a4e3ad2cdf7d23a), LL(0x69bb69d06f06d069), LL(0x091b092d48412d09),
    LL(0x709070ada7d7ad70), LL(0xb6c7b654d96f54b6), LL(0xd06dd0b7ce1eb7d0), LL(0xed2aed7e3bd67eed),
    LL(0xcc49ccdb2ee2dbcc), LL(0x42c642572a685742), LL(0x98b598c2b42cc298), LL(0xa4f1a40e49ed0ea4),
    LL(0x287828885d758828), LL(0x5ce45c31da86315c), LL(0xf815f83f936b3ff8), LL(0x869786a444c2a486),
};
#endif /* OBSOLETE */

static const u64 rc[R + 1] = {
    LL(0x0000000000000000),
    LL(0x1823c6e887b8014f),
    LL(0x36a6d2f5796f9152),
    LL(0x60bc9b8ea30c7b35),
    LL(0x1de0d7c22e4bfe57),
    LL(0x157737e59ff04ada),
    LL(0x58c9290ab1a06b85),
    LL(0xbd5d10f4cb3e0567),
    LL(0xe427418ba77d95d8),
    LL(0xfbee7c66dd17479e),
    LL(0xca2dbf07ad5a8333),
};

/**
 * The core Whirlpool transform.
 */
static void processBuffer(struct NESSIEstruct* const structpointer) {
    int i, r;
    u64 K[8];        /* the round key */
    u64 block[8];    /* mu(buffer) */
    u64 state[8];    /* the cipher state */
    u64 L[8];
    u8* buffer = structpointer->buffer;

#ifdef TRACE_INTERMEDIATE_VALUES
    printf("The 8x8 matrix Z' derived from the data-string is as follows.\n");
    for (i = 0; i < WBLOCKBYTES / 8; i++) {
        printf("    %02X %02X %02X %02X %02X %02X %02X %02X\n",
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7]);
        buffer += 8;
    }
    printf("\n");
    buffer = structpointer->buffer;
#endif /* ?TRACE_INTERMEDIATE_VALUES */

    /*
     * map the buffer to a block:
     */
    for (i = 0; i < 8; i++, buffer += 8) {
        block[i] =
            (((u64)buffer[0]) << 56) ^
            (((u64)buffer[1] & 0xffL) << 48) ^
            (((u64)buffer[2] & 0xffL) << 40) ^
            (((u64)buffer[3] & 0xffL) << 32) ^
            (((u64)buffer[4] & 0xffL) << 24) ^
            (((u64)buffer[5] & 0xffL) << 16) ^
            (((u64)buffer[6] & 0xffL) << 8) ^
            (((u64)buffer[7] & 0xffL));
    }
    /*
     * compute and apply K^0 to the cipher state:
     */
    state[0] = block[0] ^ (K[0] = structpointer->hash[0]);
    state[1] = block[1] ^ (K[1] = structpointer->hash[1]);
    state[2] = block[2] ^ (K[2] = structpointer->hash[2]);
    state[3] = block[3] ^ (K[3] = structpointer->hash[3]);
    state[4] = block[4] ^ (K[4] = structpointer->hash[4]);
    state[5] = block[5] ^ (K[5] = structpointer->hash[5]);
    state[6] = block[6] ^ (K[6] = structpointer->hash[6]);
    state[7] = block[7] ^ (K[7] = structpointer->hash[7]);
#ifdef TRACE_INTERMEDIATE_VALUES
    printf("The K_0 matrix (from the initialization value IV) and X'' matrix are as follows.\n");
    for (i = 0; i < DIGESTBYTES / 8; i++) {
        printf(
            "    %02X %02X %02X %02X %02X %02X %02X %02X        %02X %02X %02X %02X %02X %02X %02X %02X\n",
            (u8)(K[i] >> 56),
            (u8)(K[i] >> 48),
            (u8)(K[i] >> 40),
            (u8)(K[i] >> 32),
            (u8)(K[i] >> 24),
            (u8)(K[i] >> 16),
            (u8)(K[i] >> 8),
            (u8)(K[i]),

            (u8)(state[i] >> 56),
            (u8)(state[i] >> 48),
            (u8)(state[i] >> 40),
            (u8)(state[i] >> 32),
            (u8)(state[i] >> 24),
            (u8)(state[i] >> 16),
            (u8)(state[i] >> 8),
            (u8)(state[i]));
    }
    printf("\n");
    printf("The following are (hexadecimal representations of) the successive values of the variables K_i for i = 1 to 10 and W'.\n");
    printf("\n");
#endif /* ?TRACE_INTERMEDIATE_VALUES */
    /*
     * iterate over all rounds:
     */
    for (r = 1; r <= R; r++) {
        /*
         * compute K^r from K^{r-1}:
         */
        L[0] =
            C0[(int)(K[0] >> 56)] ^
            C1[(int)(K[7] >> 48) & 0xff] ^
            C2[(int)(K[6] >> 40) & 0xff] ^
            C3[(int)(K[5] >> 32) & 0xff] ^
            C4[(int)(K[4] >> 24) & 0xff] ^
            C5[(int)(K[3] >> 16) & 0xff] ^
            C6[(int)(K[2] >> 8) & 0xff] ^
            C7[(int)(K[1]) & 0xff] ^
            rc[r];
        L[1] =
            C0[(int)(K[1] >> 56)] ^
            C1[(int)(K[0] >> 48) & 0xff] ^
            C2[(int)(K[7] >> 40) & 0xff] ^
            C3[(int)(K[6] >> 32) & 0xff] ^
            C4[(int)(K[5] >> 24) & 0xff] ^
            C5[(int)(K[4] >> 16) & 0xff] ^
            C6[(int)(K[3] >> 8) & 0xff] ^
            C7[(int)(K[2]) & 0xff];
        L[2] =
            C0[(int)(K[2] >> 56)] ^
            C1[(int)(K[1] >> 48) & 0xff] ^
            C2[(int)(K[0] >> 40) & 0xff] ^
            C3[(int)(K[7] >> 32) & 0xff] ^
            C4[(int)(K[6] >> 24) & 0xff] ^
            C5[(int)(K[5] >> 16) & 0xff] ^
            C6[(int)(K[4] >> 8) & 0xff] ^
            C7[(int)(K[3]) & 0xff];
        L[3] =
            C0[(int)(K[3] >> 56)] ^
            C1[(int)(K[2] >> 48) & 0xff] ^
            C2[(int)(K[1] >> 40) & 0xff] ^
            C3[(int)(K[0] >> 32) & 0xff] ^
            C4[(int)(K[7] >> 24) & 0xff] ^
            C5[(int)(K[6] >> 16) & 0xff] ^
            C6[(int)(K[5] >> 8) & 0xff] ^
            C7[(int)(K[4]) & 0xff];
        L[4] =
            C0[(int)(K[4] >> 56)] ^
            C1[(int)(K[3] >> 48) & 0xff] ^
            C2[(int)(K[2] >> 40) & 0xff] ^
            C3[(int)(K[1] >> 32) & 0xff] ^
            C4[(int)(K[0] >> 24) & 0xff] ^
            C5[(int)(K[7] >> 16) & 0xff] ^
            C6[(int)(K[6] >> 8) & 0xff] ^
            C7[(int)(K[5]) & 0xff];
        L[5] =
            C0[(int)(K[5] >> 56)] ^
            C1[(int)(K[4] >> 48) & 0xff] ^
            C2[(int)(K[3] >> 40) & 0xff] ^
            C3[(int)(K[2] >> 32) & 0xff] ^
            C4[(int)(K[1] >> 24) & 0xff] ^
            C5[(int)(K[0] >> 16) & 0xff] ^
            C6[(int)(K[7] >> 8) & 0xff] ^
            C7[(int)(K[6]) & 0xff];
        L[6] =
            C0[(int)(K[6] >> 56)] ^
            C1[(int)(K[5] >> 48) & 0xff] ^
            C2[(int)(K[4] >> 40) & 0xff] ^
            C3[(int)(K[3] >> 32) & 0xff] ^
            C4[(int)(K[2] >> 24) & 0xff] ^
            C5[(int)(K[1] >> 16) & 0xff] ^
            C6[(int)(K[0] >> 8) & 0xff] ^
            C7[(int)(K[7]) & 0xff];
        L[7] =
            C0[(int)(K[7] >> 56)] ^
            C1[(int)(K[6] >> 48) & 0xff] ^
            C2[(int)(K[5] >> 40) & 0xff] ^
            C3[(int)(K[4] >> 32) & 0xff] ^
            C4[(int)(K[3] >> 24) & 0xff] ^
            C5[(int)(K[2] >> 16) & 0xff] ^
            C6[(int)(K[1] >> 8) & 0xff] ^
            C7[(int)(K[0]) & 0xff];
        K[0] = L[0];
        K[1] = L[1];
        K[2] = L[2];
        K[3] = L[3];
        K[4] = L[4];
        K[5] = L[5];
        K[6] = L[6];
        K[7] = L[7];
        /*
         * apply the r-th round transformation:
         */
        L[0] =
            C0[(int)(state[0] >> 56)] ^
            C1[(int)(state[7] >> 48) & 0xff] ^
            C2[(int)(state[6] >> 40) & 0xff] ^
            C3[(int)(state[5] >> 32) & 0xff] ^
            C4[(int)(state[4] >> 24) & 0xff] ^
            C5[(int)(state[3] >> 16) & 0xff] ^
            C6[(int)(state[2] >> 8) & 0xff] ^
            C7[(int)(state[1]) & 0xff] ^
            K[0];
        L[1] =
            C0[(int)(state[1] >> 56)] ^
            C1[(int)(state[0] >> 48) & 0xff] ^
            C2[(int)(state[7] >> 40) & 0xff] ^
            C3[(int)(state[6] >> 32) & 0xff] ^
            C4[(int)(state[5] >> 24) & 0xff] ^
            C5[(int)(state[4] >> 16) & 0xff] ^
            C6[(int)(state[3] >> 8) & 0xff] ^
            C7[(int)(state[2]) & 0xff] ^
            K[1];
        L[2] =
            C0[(int)(state[2] >> 56)] ^
            C1[(int)(state[1] >> 48) & 0xff] ^
            C2[(int)(state[0] >> 40) & 0xff] ^
            C3[(int)(state[7] >> 32) & 0xff] ^
            C4[(int)(state[6] >> 24) & 0xff] ^
            C5[(int)(state[5] >> 16) & 0xff] ^
            C6[(int)(state[4] >> 8) & 0xff] ^
            C7[(int)(state[3]) & 0xff] ^
            K[2];
        L[3] =
            C0[(int)(state[3] >> 56)] ^
            C1[(int)(state[2] >> 48) & 0xff] ^
            C2[(int)(state[1] >> 40) & 0xff] ^
            C3[(int)(state[0] >> 32) & 0xff] ^
            C4[(int)(state[7] >> 24) & 0xff] ^
            C5[(int)(state[6] >> 16) & 0xff] ^
            C6[(int)(state[5] >> 8) & 0xff] ^
            C7[(int)(state[4]) & 0xff] ^
            K[3];
        L[4] =
            C0[(int)(state[4] >> 56)] ^
            C1[(int)(state[3] >> 48) & 0xff] ^
            C2[(int)(state[2] >> 40) & 0xff] ^
            C3[(int)(state[1] >> 32) & 0xff] ^
            C4[(int)(state[0] >> 24) & 0xff] ^
            C5[(int)(state[7] >> 16) & 0xff] ^
            C6[(int)(state[6] >> 8) & 0xff] ^
            C7[(int)(state[5]) & 0xff] ^
            K[4];
        L[5] =
            C0[(int)(state[5] >> 56)] ^
            C1[(int)(state[4] >> 48) & 0xff] ^
            C2[(int)(state[3] >> 40) & 0xff] ^
            C3[(int)(state[2] >> 32) & 0xff] ^
            C4[(int)(state[1] >> 24) & 0xff] ^
            C5[(int)(state[0] >> 16) & 0xff] ^
            C6[(int)(state[7] >> 8) & 0xff] ^
            C7[(int)(state[6]) & 0xff] ^
            K[5];
        L[6] =
            C0[(int)(state[6] >> 56)] ^
            C1[(int)(state[5] >> 48) & 0xff] ^
            C2[(int)(state[4] >> 40) & 0xff] ^
            C3[(int)(state[3] >> 32) & 0xff] ^
            C4[(int)(state[2] >> 24) & 0xff] ^
            C5[(int)(state[1] >> 16) & 0xff] ^
            C6[(int)(state[0] >> 8) & 0xff] ^
            C7[(int)(state[7]) & 0xff] ^
            K[6];
        L[7] =
            C0[(int)(state[7] >> 56)] ^
            C1[(int)(state[6] >> 48) & 0xff] ^
            C2[(int)(state[5] >> 40) & 0xff] ^
            C3[(int)(state[4] >> 32) & 0xff] ^
            C4[(int)(state[3] >> 24) & 0xff] ^
            C5[(int)(state[2] >> 16) & 0xff] ^
            C6[(int)(state[1] >> 8) & 0xff] ^
            C7[(int)(state[0]) & 0xff] ^
            K[7];
        state[0] = L[0];
        state[1] = L[1];
        state[2] = L[2];
        state[3] = L[3];
        state[4] = L[4];
        state[5] = L[5];
        state[6] = L[6];
        state[7] = L[7];
#ifdef TRACE_INTERMEDIATE_VALUES
        printf("i = %d:\n", r);
        for (i = 0; i < DIGESTBYTES / 8; i++) {
            printf(
                "    %02X %02X %02X %02X %02X %02X %02X %02X        %02X %02X %02X %02X %02X %02X %02X %02X\n",
                (u8)(K[i] >> 56),
                (u8)(K[i] >> 48),
                (u8)(K[i] >> 40),
                (u8)(K[i] >> 32),
                (u8)(K[i] >> 24),
                (u8)(K[i] >> 16),
                (u8)(K[i] >> 8),
                (u8)(K[i]),

                (u8)(state[i] >> 56),
                (u8)(state[i] >> 48),
                (u8)(state[i] >> 40),
                (u8)(state[i] >> 32),
                (u8)(state[i] >> 24),
                (u8)(state[i] >> 16),
                (u8)(state[i] >> 8),
                (u8)(state[i]));
        }
        printf("\n");
#endif /* ?TRACE_INTERMEDIATE_VALUES */
    }
    /*
     * apply the Miyaguchi-Preneel compression function:
     */
    structpointer->hash[0] ^= state[0] ^ block[0];
    structpointer->hash[1] ^= state[1] ^ block[1];
    structpointer->hash[2] ^= state[2] ^ block[2];
    structpointer->hash[3] ^= state[3] ^ block[3];
    structpointer->hash[4] ^= state[4] ^ block[4];
    structpointer->hash[5] ^= state[5] ^ block[5];
    structpointer->hash[6] ^= state[6] ^ block[6];
    structpointer->hash[7] ^= state[7] ^ block[7];
#ifdef TRACE_INTERMEDIATE_VALUES
    //printf("Intermediate hash value (after Miyaguchi-Preneel):\n");
    printf("The value of Y' output from the round-function is as follows.\n");
    for (i = 0; i < DIGESTBYTES / 8; i++) {
        printf("    %02X %02X %02X %02X %02X %02X %02X %02X\n",
            (u8)(structpointer->hash[i] >> 56),
            (u8)(structpointer->hash[i] >> 48),
            (u8)(structpointer->hash[i] >> 40),
            (u8)(structpointer->hash[i] >> 32),
            (u8)(structpointer->hash[i] >> 24),
            (u8)(structpointer->hash[i] >> 16),
            (u8)(structpointer->hash[i] >> 8),
            (u8)(structpointer->hash[i]));
    }
    printf("\n");
#endif /* ?TRACE_INTERMEDIATE_VALUES */
}

/**
 * Initialize the hashing state.
 */
void NESSIEinit(struct NESSIEstruct* const structpointer) {
    int i;

    memset(structpointer->bitLength, 0, 32);
    structpointer->bufferBits = structpointer->bufferPos = 0;
    structpointer->buffer[0] = 0; /* it's only necessary to cleanup buffer[bufferPos] */
    for (i = 0; i < 8; i++) {
        structpointer->hash[i] = 0L; /* initial value */
    }
#ifdef TRACE_INTERMEDIATE_VALUES
    /*
    printf("Initial hash value:\n");
    for (i = 0; i < DIGESTBYTES/8; i++) {
        printf("    %02X %02X %02X %02X %02X %02X %02X %02X\n",
            (u8)(structpointer->hash[i] >> 56),
            (u8)(structpointer->hash[i] >> 48),
            (u8)(structpointer->hash[i] >> 40),
            (u8)(structpointer->hash[i] >> 32),
            (u8)(structpointer->hash[i] >> 24),
            (u8)(structpointer->hash[i] >> 16),
            (u8)(structpointer->hash[i] >>  8),
            (u8)(structpointer->hash[i]      ));
    }
    printf("\n");
    */
#endif /* ?TRACE_INTERMEDIATE_VALUES */
}

/**
 * Delivers input data to the hashing algorithm.
 *
 * @param    source        plaintext data to hash.
 * @param    sourceBits    how many bits of plaintext to process.
 *
 * This method maintains the invariant: bufferBits < DIGESTBITS
 */
void NESSIEadd(const unsigned char* const source,
    unsigned long sourceBits,
    struct NESSIEstruct* const structpointer) {
    /*
                       sourcePos
                       |
                       +-------+-------+-------
                          ||||||||||||||||||||| source
                       +-------+-------+-------
    +-------+-------+-------+-------+-------+-------
    ||||||||||||||||||||||                           buffer
    +-------+-------+-------+-------+-------+-------
                    |
                    bufferPos
    */
    int sourcePos = 0; /* index of leftmost source u8 containing data (1 to 8 bits). */
    int sourceGap = (8 - ((int)sourceBits & 7)) & 7; /* space on source[sourcePos]. */
    int bufferRem = structpointer->bufferBits & 7; /* occupied bits on buffer[bufferPos]. */
    int i;
    u32 b, carry;
    u8* buffer = structpointer->buffer;
    u8* bitLength = structpointer->bitLength;
    int bufferBits = structpointer->bufferBits;
    int bufferPos = structpointer->bufferPos;

    /*
     * tally the length of the added data:
     */
    u64 value = sourceBits;
    for (i = 31, carry = 0; i >= 0 && (carry != 0 || value != LL(0)); i--) {
        carry += bitLength[i] + ((u32)value & 0xff);
        bitLength[i] = (u8)carry;
        carry >>= 8;
        value >>= 8;
    }
    /*
     * process data in chunks of 8 bits (a more efficient approach would be to take whole-word chunks):
     */
    while (sourceBits > 8) {
        /* N.B. at least source[sourcePos] and source[sourcePos+1] contain data. */
        /*
         * take a byte from the source:
         */
        b = ((source[sourcePos] << sourceGap) & 0xff) |
            ((source[sourcePos + 1] & 0xff) >> (8 - sourceGap));
        /*
         * process this byte:
         */
        buffer[bufferPos++] |= (u8)(b >> bufferRem);
        bufferBits += 8 - bufferRem; /* bufferBits = 8*bufferPos; */
        if (bufferBits == DIGESTBITS) {
            /*
             * process data block:
             */
            processBuffer(structpointer);
            /*
             * reset buffer:
             */
            bufferBits = bufferPos = 0;
        }
        buffer[bufferPos] = b << (8 - bufferRem);
        bufferBits += bufferRem;
        /*
         * proceed to remaining data:
         */
        sourceBits -= 8;
        sourcePos++;
    }
    /* now 0 <= sourceBits <= 8;
     * furthermore, all data (if any is left) is in source[sourcePos].
     */
    if (sourceBits > 0) {
        b = (source[sourcePos] << sourceGap) & 0xff; /* bits are left-justified on b. */
        /*
         * process the remaining bits:
         */
        buffer[bufferPos] |= b >> bufferRem;
    }
    else {
        b = 0;
    }
    if (bufferRem + sourceBits < 8) {
        /*
         * all remaining data fits on buffer[bufferPos],
         * and there still remains some space.
         */
        bufferBits += sourceBits;
    }
    else {
        /*
         * buffer[bufferPos] is full:
         */
        bufferPos++;
        bufferBits += 8 - bufferRem; /* bufferBits = 8*bufferPos; */
        sourceBits -= 8 - bufferRem;
        /* now 0 <= sourceBits < 8;
         * furthermore, all data (if any is left) is in source[sourcePos].
         */
        if (bufferBits == DIGESTBITS) {
            /*
             * process data block:
             */
            processBuffer(structpointer);
            /*
             * reset buffer:
             */
            bufferBits = bufferPos = 0;
        }
        buffer[bufferPos] = b << (8 - bufferRem);
        bufferBits += (int)sourceBits;
    }
    structpointer->bufferBits = bufferBits;
    structpointer->bufferPos = bufferPos;
}

/**
 * Get the hash value from the hashing state.
 *
 * This method uses the invariant: bufferBits < DIGESTBITS
 */
void NESSIEfinalize(struct NESSIEstruct* const structpointer,
    unsigned char* const result) {
    int i;
    u8* buffer = structpointer->buffer;
    u8* bitLength = structpointer->bitLength;
    int bufferBits = structpointer->bufferBits;
    int bufferPos = structpointer->bufferPos;
    u8* digest = result;

    /*
     * append a '1'-bit:
     */
    buffer[bufferPos] |= 0x80U >> (bufferBits & 7);
    bufferPos++; /* all remaining bits on the current u8 are set to zero. */
    /*
     * pad with zero bits to complete (N*WBLOCKBITS - LENGTHBITS) bits:
     */
    if (bufferPos > WBLOCKBYTES - LENGTHBYTES) {
        if (bufferPos < WBLOCKBYTES) {
            memset(&buffer[bufferPos], 0, WBLOCKBYTES - bufferPos);
        }
        /*
         * process data block:
         */
        processBuffer(structpointer);
        /*
         * reset buffer:
         */
        bufferPos = 0;
    }
    if (bufferPos < WBLOCKBYTES - LENGTHBYTES) {
        memset(&buffer[bufferPos], 0, (WBLOCKBYTES - LENGTHBYTES) - bufferPos);
    }
    bufferPos = WBLOCKBYTES - LENGTHBYTES;
    /*
     * append bit length of hashed data:
     */
    memcpy(&buffer[WBLOCKBYTES - LENGTHBYTES], bitLength, LENGTHBYTES);
    /*
     * process data block:
     */
    processBuffer(structpointer);
    /*
     * return the completed message digest:
     */
    for (i = 0; i < DIGESTBYTES / 8; i++) {
        digest[0] = (u8)(structpointer->hash[i] >> 56);
        digest[1] = (u8)(structpointer->hash[i] >> 48);
        digest[2] = (u8)(structpointer->hash[i] >> 40);
        digest[3] = (u8)(structpointer->hash[i] >> 32);
        digest[4] = (u8)(structpointer->hash[i] >> 24);
        digest[5] = (u8)(structpointer->hash[i] >> 16);
        digest[6] = (u8)(structpointer->hash[i] >> 8);
        digest[7] = (u8)(structpointer->hash[i]);
        digest += 8;
    }
    structpointer->bufferBits = bufferBits;
    structpointer->bufferPos = bufferPos;
}

static void display(const u8 array[], int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (i % 32 == 0) {
            printf("\n");
        }
        if (i % 8 == 0) {
            printf(" ");
        }
        printf("%02X", array[i]);
    }
}

#define LONG_ITERATION 100000000

/**
 * Generate the test vector set for Whirlpool.
 *
 * The test consists of:
 * 1. hashing all bit strings containing only zero bits
 *    for all lengths from 0 to 1023;
 * 2. hashing all 512-bit strings containing a single set bit;
 * 3. the iterated hashing of the 512-bit string of zero bits a large number of times.
 */
void makeNESSIETestVectors() {
    int i;
    struct NESSIEstruct w;
    u8 digest[DIGESTBYTES];
    u8 data[128];

    memset(data, 0, sizeof(data));
    printf("Message digests of strings of 0-bits and length L:\n");
    for (i = 0; i < 1024; i++) {
        NESSIEinit(&w);
        NESSIEadd(data, i, &w);
        NESSIEfinalize(&w, digest);
        printf("    L = %4d: ", i); display(digest, DIGESTBYTES); printf("\n");
    }
    printf("Message digests of all 512-bit strings S containing a single 1-bit:\n");
    memset(data, 0, sizeof(data));
    for (i = 0; i < 512; i++) {
        /* set bit i: */
        data[i / 8] |= 0x80U >> (i % 8);
        NESSIEinit(&w);
        NESSIEadd(data, 512, &w);
        NESSIEfinalize(&w, digest);
        printf("    S = "); display(data, 512 / 8); printf(": ");
        display(digest, DIGESTBYTES); printf("\n");
        /* reset bit i: */
        data[i / 8] = 0;
    }
    memset(digest, 0, sizeof(digest));
    for (i = 0; i < LONG_ITERATION; i++) {
        NESSIEinit(&w);
        NESSIEadd(digest, 512, &w);
        NESSIEfinalize(&w, digest);
    }
    fflush(stdout);
    printf("Iterated message digest computation (%d times): ", LONG_ITERATION);
    display(digest, DIGESTBYTES); printf("\n");
}



/*
#define TIMING_ITERATIONS 100000

static void timing() {
    int i;
    NESSIEstruct w;
    u8 digest[DIGESTBYTES];
    u8 data[1024];
    clock_t elapsed;
    float sec;

    memset(data, 0, sizeof(data));

    printf("Overall timing...");
    elapsed = -clock();
    for (i = 0; i < TIMING_ITERATIONS; i++) {
        NESSIEinit(&w);
        NESSIEadd(data, 8*sizeof(data), &w);
        NESSIEfinalize(&w, digest);
    }
    elapsed += clock();
    sec = (float)elapsed/CLOCKS_PER_SEC;
    printf(" %.1f s, %.1f Mbit/s, %.1f cycles/byte.\n",
        sec,
        (float)8*sizeof(data)*TIMING_ITERATIONS/sec/1000000,
        (float)550e6*sec/(sizeof(data)*TIMING_ITERATIONS));

    printf("Compression function timing...");
    NESSIEinit(&w);
    elapsed = -clock();
    for (i = 0; i < TIMING_ITERATIONS; i++) {
        processBuffer(&w);
    }
    elapsed += clock();
    NESSIEfinalize(&w, digest);
    sec = (float)elapsed/CLOCKS_PER_SEC;
    printf(" %.1f s, %.1f Mbit/s, %.1f cycles/byte.\n",
        sec,
        (float)512*TIMING_ITERATIONS/sec/1000000,
        (float)550e6*sec/(64*TIMING_ITERATIONS));
}
*/

#ifdef TRACE_INTERMEDIATE_VALUES
static void makeIntermediateValues() {
    struct NESSIEstruct w;
    u8 digest[DIGESTBYTES];

    printf("3. In this example the data-string is the three-byte string consisting of the ASCII-coded version of 'abc'.\n\n");
    NESSIEinit(&w);
    NESSIEadd("abc", 8 * 3, &w);
    NESSIEfinalize(&w, digest);
    printf("The hash-code is the following 512-bit string.\n\n");
    display(digest, DIGESTBYTES); printf("\n\n");

    printf("8. In this example the data-string is the 32-byte string consisting of the ASCII-coded version of 'abcdbcdecdefdefgefghfghighijhijk'.\n\n");
    NESSIEinit(&w);
    NESSIEadd("abcdbcdecdefdefgefghfghighijhijk", 8 * 32, &w);
    NESSIEfinalize(&w, digest);
    printf("The hash-code is the following 512-bit string.\n\n");
    display(digest, DIGESTBYTES); printf("\n\n");
    fflush(stdout);

    fflush(stdout);
}
#endif /* ?TRACE_INTERMEDIATE_VALUES */

#if 0
int main(int argc, char* argv[]) {
    /* testAPI(); */
    /* makeNESSIETestVectors(); */
    makeISOTestVectors();
#ifdef TRACE_INTERMEDIATE_VALUES
    makeIntermediateValues();
#endif /* ?TRACE_INTERMEDIATE_VALUES */
    /* timing(); */
    return 0;
}
#endif

#if defined (_MSC_VER)
#pragma warning(pop)
#endif
