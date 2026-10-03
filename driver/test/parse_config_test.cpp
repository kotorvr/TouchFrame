// Host test: the configs tools/touchplus_config.py writes must pass the driver's parser.
// Build (any C++17 compiler, no SteamVR needed):  see driver/test/run.sh
#include <cstdio>
#include <fstream>
#include <sstream>

#include "cv_tracker.h"

int main(int argc, char** argv) {
    int fails = 0;
    for (int i = 1; i < argc; i++) {
        std::ifstream f(argv[i]);
        std::stringstream ss;
        ss << f.rdbuf();
        tf::cv::ControllerConfig c;
        std::string err;
        if (!tf::cv::ParseControllerConfig(ss.str(), &c, &err)) {
            printf("FAIL %s: %s\n", argv[i], err.c_str());
            fails++;
            continue;
        }
        tf::cv::Pose h = tf::cv::HeadFromPoseBlock(c);
        printf("ok   %s: serial %s model %s role %s, %d LEDs, %zu bytes, head_from_poseblock p=(%.4f %.4f %.4f)\n",
               argv[i], c.serial.c_str(), c.model_number.c_str(), c.role.c_str(), c.led_count, c.json.size(), h.p.x,
               h.p.y, h.p.z);
    }
    return fails;
}
