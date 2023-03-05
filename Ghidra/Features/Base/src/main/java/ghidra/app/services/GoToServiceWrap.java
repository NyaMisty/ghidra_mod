/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.services;

import ghidra.app.nav.Navigatable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

public class GoToServiceWrap implements GoToService {
    public GoToService gotoService;
    public GoToServiceWrap(GoToService gotoService) {
        this.gotoService = gotoService;
    }

    @Override
    public boolean goTo(ProgramLocation loc) {
        return gotoService.goTo(loc);
    }

    @Override
    public boolean goTo(ProgramLocation loc, Program program) {
        return gotoService.goTo(loc, program);
    }

    @Override
    public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
        return gotoService.goTo(navigatable, loc, program);
    }

    @Override
    public boolean goTo(Navigatable navigatable, Program program, Address address, Address refAddress) {
        return gotoService.goTo(navigatable, program, address, refAddress);
    }

    @Override
    public boolean goTo(Address fromAddress, Address address) {
        return gotoService.goTo(fromAddress, address);
    }

    @Override
    public boolean goTo(Navigatable navigatable, Address goToAddress) {
        return gotoService.goTo(navigatable, goToAddress);
    }

    @Override
    public boolean goTo(Address goToAddress) {
        return gotoService.goTo(goToAddress);
    }

    @Override
    public boolean goTo(Address goToAddress, Program program) {
        return gotoService.goTo(goToAddress, program);
    }

    @Override
    public boolean goToExternalLocation(ExternalLocation externalLoc, boolean checkNavigationOption) {
        return gotoService.goToExternalLocation(externalLoc, checkNavigationOption);
    }

    @Override
    public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation externalLoc, boolean checkNavigationOption) {
        return gotoService.goToExternalLocation(navigatable, externalLoc, checkNavigationOption);
    }

    @Override
    public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener, TaskMonitor monitor) {
        return gotoService.goToQuery(fromAddr, queryData, listener, monitor);
    }

    @Override
    public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData, GoToServiceListener listener, TaskMonitor monitor) {
        return gotoService.goToQuery(navigatable, fromAddr, queryData, listener, monitor);
    }

    @Override
    public Navigatable getDefaultNavigatable() {
        return gotoService.getDefaultNavigatable();
    }

    @Override
    public GoToOverrideService getOverrideService() {
        return gotoService.getOverrideService();
    }

    @Override
    public void setOverrideService(GoToOverrideService override) {
        gotoService.setOverrideService(override);
    }
}
