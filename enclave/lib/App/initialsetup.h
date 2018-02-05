#ifndef COMMPACT_INITIALSETUP_H
#define COMMPACT_INITIALSETUP_H

#define COMMPACT_MAX_ENCLAVES 8

// NOTE:
// THIS ENTIRE SINGLETON CLASS IS A HACK
// We need a simple mechanism during simulation start to aggregate the
// vehicles' public keys and pass them between one another since we're not
// currently implementing the Join Procedure (in which the vehicles would
// explicitly pass their pubkeys to one another over the network).  Since new
// vehicles can be added in veins at any time, we're using the
// setInitialPosition() function for each vehicle to keep track of its platoon
// position. After each vehicle sets its initial position, it will also
// generate a keypair. Its pubkey will be added to the pubkey_list[] below, and
// all enclaves will be updated with this new list.

struct InitialSetup {
public:
  static InitialSetup &getInstance() {
    static InitialSetup instance;
    return instance;
  }
  InitialSetup(InitialSetup const &) = delete;
  InitialSetup(InitialSetup &&) = delete;
  void operator=(InitialSetup const &) = delete;

  int getPosition(uint64_t enclave_id) {
    for (int i = 0; i < COMMPACT_MAX_ENCLAVES; i++) {
      if (enclave_id_list[i] == enclave_id) {
        return i;
      }
    }
    return -1;
  }

private:
  InitialSetup() {}

public:
  // put struct members here

  // these arrays are indexed by platoon position
  uint8_t n_vehicles = 0;
  bool used_list[COMMPACT_MAX_ENCLAVES] = {0};
  uint64_t enclave_id_list[COMMPACT_MAX_ENCLAVES];
  cp_ec256_public_t pubkey_list[COMMPACT_MAX_ENCLAVES];
};

#endif // COMMPACT_INITIALSETUP_H
