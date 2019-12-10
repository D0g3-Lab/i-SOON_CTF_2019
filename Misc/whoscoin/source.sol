pragma solidity ^0.4.18;

contract Whoscoin {
    
    uint256 private constant _INITIAL_SUPPLY = 15*10**27;
    uint8 public decimals = 18;         
    uint256 public totalSupply;
    address public owner;

    mapping (address => uint256) balances; 
    mapping (address => mapping (address => uint256)) allowed;

    event sendFlag(string b64email, string slogan);

    function Whoscoin() public {
        balances[msg.sender] = _INITIAL_SUPPLY;
        totalSupply = _INITIAL_SUPPLY;
        owner = msg.sender;
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);
        require(balances[_from] >= _value);
        require(balances[_to] + _value > balances[_to]);
    
        uint previousBalances = balances[_from] + balances[_to];
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;
        assert(balances[_from] + balances[_to] == previousBalances);
    
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        return true;
    }
    
    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }
    
    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
          owner = _owner;
        }
    }

    function payforflag(string b64email) public {
        require(balanceOf(msg.sender) >= 10000);
        require(owner == msg.sender);
        sendFlag(b64email, "bravo!");
        
    }

}